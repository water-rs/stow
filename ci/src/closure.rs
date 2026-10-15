//! The set of crates a task is allowed to publish artifacts for.
//!
//! The build job runs third-party build scripts and proc-macros, so nothing
//! it hands over can be trusted to describe which crates it compiled. The
//! publisher reads the set itself, from a fresh crates.io download it alone
//! touched: cargo's own `--unit-graph` for the phases the build ran, which
//! plans the whole compilation — every unit, on the side it compiles — and
//! executes no crate code. A planned artifact whose crate is in no phase's
//! unit graph is a fabrication and is refused; every crates.io package whose
//! library unit a `build`-phase graph compiles must appear in the plan.
//!
//! `cargo tree` and `cargo metadata` each approximated that set and each
//! over-reported in its own way: the tree follows a build-dependency edge
//! out of a package that has no build script (`derive_more-impl 2.1.1`
//! publishes `build = false` beside `[build-dependencies] rustc_version`),
//! and the metadata resolve graph keeps a feature edge nothing the task
//! selected activated (`self_update`'s `zipsign-api` chain into
//! `curve25519-dalek`). Intersecting two over-reports is still not the
//! compiled set — it demanded a `rustc_version` artifact for a crate cargo
//! never compiled (stow#726).
//!
//! The publishable set is defined by the `check` and `build` phases, so
//! dev-dependencies — which only the `test` phase's graph compiles — and
//! dependencies of other platforms are outside it, and an artifact
//! claiming one is a fabrication. (`STOW_BUILD_CARGO_SUBCOMMAND=test`
//! compiles dev-dependencies as well; their artifacts are not publishable
//! and the closure rejects them.)
//!
//! Resolution happens in the generated wrapper package the build job
//! compiled in, not merely with its toolchain and features: the task crate
//! resolves as the wrapper's `=<version>` registry dependency. Resolving it
//! as the root package would unify its dev-dependency feature requests into
//! the normal graph — `digest`'s `blobby` behind the `dev` feature `sha2`
//! asks for — and the unit graphs would then carry a package the build,
//! which compiles the crate as somebody else's dependency, never compiles.
//! The wrapper itself is a path package, never a crates.io unit, so it is
//! outside the closure by construction.

use std::collections::BTreeSet;

use stow_types::api::BuildTaskPayload;
use stow_types::error::Context;
use stow_types::unit_graph::{TaskUnit, TaskUnitKind};
use tempfile::TempDir;

use crate::task::{self, CargoSubcommand};

/// `(crate name, version)` pairs the task may publish, plus the subset
/// whose library target the trusted pipeline compiles — the plan must carry
/// a build-phase artifact for each of those, not merely stay inside the
/// closure. `dependency_identity` is the Merkle digest the pristine
/// workspace's own unit graphs verified against the task id (stow#588).
#[derive(Debug)]
pub struct DependencyClosure {
    packages: BTreeSet<(String, semver::Version)>,
    lib_packages: BTreeSet<(String, semver::Version)>,
    dependency_identity: stow_types::identity::DependencyIdentity,
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

    /// The dependency-context digest the publisher verified from its own
    /// workspace — every planned artifact's `dependency_identity` must
    /// equal it.
    #[must_use]
    pub const fn dependency_identity(&self) -> &stow_types::identity::DependencyIdentity {
        &self.dependency_identity
    }

    #[must_use]
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }

    #[cfg(test)]
    pub(crate) fn from_packages(
        packages: BTreeSet<(String, semver::Version)>,
        lib_packages: BTreeSet<(String, semver::Version)>,
    ) -> Self {
        Self {
            packages,
            lib_packages,
            // Test closures carry no derived graph; the leaf digest stands
            // in for the digest a real `resolve` would have verified.
            dependency_identity: stow_types::identity::DependencyIdentity::leaf()
                .expect("leaf digest"),
        }
    }
}

/// Resolve the closure for `task` exactly the way the build job did — same
/// toolchain, same feature set, same lockfile policy — but from a pristine
/// source tree.
pub async fn resolve(task: &BuildTaskPayload) -> stow_types::error::Result<DependencyClosure> {
    // Same once-per-task check the build makes: the closure must resolve
    // under the task's pinned release — refuse before the first cargo.
    task::verified_run_toolchain(task)?;
    let root = TempDir::new().wrap_err("create closure resolution workspace")?;
    // The task resolves as a dependency of the generated wrapper package,
    // exactly as the build job compiled it — the wrapper decides which
    // packages cargo resolves, not merely where they sit on disk.
    let manifest_path = task::create_resolution_workspace(task, root.path()).await?;
    let workspace = task::resolution_build_workspace(
        manifest_path.clone(),
        manifest_path
            .parent()
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "resolution workspace manifest {} has no parent",
                    manifest_path.display()
                )
            })?
            .to_path_buf(),
    );
    task::fetch_workspace_dependencies(task, &workspace).await?;
    // stow#588: the publisher verifies the dependency context the same
    // way the build job does — the pristine wrapper workspace's own
    // `cargo --unit-graph` answers projected onto the shared task-unit
    // model must mint the dispatched task id in every phase and
    // invocation spelling. The same graphs then answer the publishable
    // set: they are the exact set of units cargo planned to compile.
    let unit_graphs = task::phase_unit_graphs(task, &workspace, task::cargo_subcommand()?).await?;
    task::verify_dependency_context(task, &unit_graphs)?;
    let (packages, lib_packages) = package_sets(task, &unit_graphs)?;
    let dependency_identity = task
        .verified_dependency_graph()?
        .dependency_identity(0)
        .ok_or_else(|| stow_types::stow_error!("verified dependency graph has no root digest"))?
        .clone();
    tracing::info!(
        crate_name = %task.crate_name,
        version = %task.version,
        packages = packages.len(),
        "resolved publishable dependency closure"
    );
    Ok(DependencyClosure {
        packages,
        lib_packages,
        dependency_identity,
    })
}

/// One phase's units as the closure reads them: which subcommand's graph
/// they came from decides what they may join — `check` and `build` graphs
/// name publishable packages, only a `build` graph demands coverage, and a
/// `test` graph's units are dev-dependencies no plan may name.
struct PhaseUnits {
    phase: CargoSubcommand,
    units: Vec<TaskUnit>,
}

/// Every phase×invocation graph's units projected once, tagged with the
/// phase each answers for — the host triple is the one
/// `verify_dependency_context` resolves the same graphs at.
fn phase_units(
    task: &BuildTaskPayload,
    unit_graphs: &[task::PhaseUnitGraph],
) -> stow_types::error::Result<Vec<PhaseUnits>> {
    let host_triple = task::runner_host_triple(task)?;
    unit_graphs
        .iter()
        .map(|graph| {
            let units = graph.task_units(host_triple).map_err(|error| {
                stow_types::stow_error!(
                    "task {} {} ({}): {} unit graph does not convert: {error}",
                    task.crate_name.as_str(),
                    task.version,
                    task.target,
                    graph.label(),
                )
            })?;
            Ok(PhaseUnits {
                phase: graph.phase(),
                units,
            })
        })
        .collect()
}

/// `(packages, lib_packages)` — the two sets `closure_packages` returns:
/// crates the plan may name, and the subset it must carry an artifact for.
type PackageSets = (
    BTreeSet<(String, semver::Version)>,
    BTreeSet<(String, semver::Version)>,
);

/// `resolve`'s pure half: the projected phase graphs in, the publishable
/// and demanded package sets out.
pub fn package_sets(
    task: &BuildTaskPayload,
    unit_graphs: &[task::PhaseUnitGraph],
) -> stow_types::error::Result<PackageSets> {
    closure_packages(task, &phase_units(task, unit_graphs)?)
}

/// The two sets a publish plan is checked against, from the phases' own
/// unit graphs: every crates.io package a `check` or `build` graph holds a
/// unit of is one the plan may name, and every one whose `build`-phase
/// graph holds its library unit is one the plan must carry an artifact
/// for. A unit only a `test`-phase graph holds is a dev-dependency —
/// compiled, never publishable.
fn closure_packages(
    task: &BuildTaskPayload,
    phases: &[PhaseUnits],
) -> stow_types::error::Result<PackageSets> {
    let mut packages = BTreeSet::new();
    let mut lib_packages = BTreeSet::new();
    for phase in phases {
        if phase.phase == CargoSubcommand::Test {
            continue;
        }
        for unit in &phase.units {
            if !unit.is_crates_io {
                continue;
            }
            let version = semver::Version::parse(&unit.version).map_err(|error| {
                stow_types::stow_error!(
                    "unit graph reports {} at a version that is not semver ({}): {error}",
                    unit.name,
                    unit.version
                )
            })?;
            let key = (unit.name.clone(), version);
            packages.insert(key.clone());
            if phase.phase == CargoSubcommand::Build && unit.key.kind == TaskUnitKind::Lib {
                lib_packages.insert(key);
            }
        }
    }
    if packages.is_empty() {
        return Err(stow_types::stow_error!(
            "the unit graphs of {} {} hold no crates.io package",
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
    Ok((packages, lib_packages))
}

#[cfg(test)]
mod tests {
    use stow_types::api::BuildTaskPayload;
    use stow_types::identity::{
        CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
    };
    use stow_types::unit_graph::{TaskUnit, TaskUnitKey, TaskUnitKind, TaskUnitSide};

    use super::{PhaseUnits, closure_packages};
    use crate::task::CargoSubcommand;

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
            host_side: false,
            explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
            dependency_subgraph: stow_types::api::TaskSubgraph {
                root_deps: Vec::new(),
                nodes: Vec::new(),
            },
        }
    }

    /// A crates.io unit of `kind` — the shape `task_units` projects a
    /// `registry+…` pkg id into, whichever phase's graph carried it.
    fn unit(name: &str, version: &str, kind: TaskUnitKind) -> TaskUnit {
        TaskUnit {
            key: TaskUnitKey {
                pkg: format!(
                    "registry+https://github.com/rust-lang/crates.io-index#{name}@{version}"
                ),
                platform: "x86_64-unknown-linux-gnu".to_owned(),
                side: TaskUnitSide::Target,
                kind,
            },
            name: name.to_owned(),
            version: version.to_owned(),
            features: Vec::new(),
            is_crates_io: true,
            deps: Vec::new(),
        }
    }

    /// A `path+` unit — the generated wrapper package, which compiles
    /// like everything else in the graph but is never publishable.
    fn path_unit(name: &str, version: &str) -> TaskUnit {
        TaskUnit {
            key: TaskUnitKey {
                pkg: format!("path+file:///tmp/closure/wrapper#{version}"),
                platform: "x86_64-unknown-linux-gnu".to_owned(),
                side: TaskUnitSide::Target,
                kind: TaskUnitKind::Lib,
            },
            name: name.to_owned(),
            version: version.to_owned(),
            features: Vec::new(),
            is_crates_io: false,
            deps: Vec::new(),
        }
    }

    fn phase(phase: CargoSubcommand, units: Vec<TaskUnit>) -> PhaseUnits {
        PhaseUnits { phase, units }
    }

    fn pair(name: &str, version: &str) -> (String, semver::Version) {
        (
            name.to_owned(),
            semver::Version::parse(version).expect("semver"),
        )
    }

    #[test]
    fn a_package_with_a_lib_unit_in_the_build_phase_must_be_covered() {
        // A lib unit in a `build` graph is a crate the pipeline compiles —
        // publishable, and the plan must carry its artifact.
        let (packages, lib_packages) = closure_packages(
            &task(),
            &[phase(
                CargoSubcommand::Build,
                vec![
                    unit("demo", "1.0.0", TaskUnitKind::Lib),
                    unit("helper", "2.0.0", TaskUnitKind::Lib),
                ],
            )],
        )
        .unwrap();
        assert!(lib_packages.contains(&pair("helper", "2.0.0")));
        assert!(packages.contains(&pair("helper", "2.0.0")));
    }

    #[test]
    fn a_package_with_only_build_script_units_is_publishable_but_not_demanded() {
        // A build-script compile unit is not the library target the cache
        // serves: the package is inside the graph, so an artifact naming it
        // is no fabrication, but the plan is not demanded to carry one.
        let (packages, lib_packages) = closure_packages(
            &task(),
            &[phase(
                CargoSubcommand::Build,
                vec![
                    unit("demo", "1.0.0", TaskUnitKind::Lib),
                    unit("rustc_version", "0.4.1", TaskUnitKind::BuildScript),
                ],
            )],
        )
        .unwrap();
        assert!(packages.contains(&pair("rustc_version", "0.4.1")));
        assert!(!lib_packages.contains(&pair("rustc_version", "0.4.1")));
    }

    #[test]
    fn a_lib_unit_only_the_check_phase_holds_is_not_demanded() {
        // `cargo check` compiles libraries too, so a check-phase unit is
        // publishable — but it proves no `build` artifact exists to demand.
        let (packages, lib_packages) = closure_packages(
            &task(),
            &[
                phase(
                    CargoSubcommand::Check,
                    vec![
                        unit("demo", "1.0.0", TaskUnitKind::Lib),
                        unit("meta_only", "2.0.0", TaskUnitKind::Lib),
                    ],
                ),
                phase(
                    CargoSubcommand::Build,
                    vec![unit("demo", "1.0.0", TaskUnitKind::Lib)],
                ),
            ],
        )
        .unwrap();
        assert!(packages.contains(&pair("meta_only", "2.0.0")));
        assert!(!lib_packages.contains(&pair("meta_only", "2.0.0")));
    }

    #[test]
    fn a_unit_only_the_test_phase_holds_is_outside_the_closure() {
        // The `test` phase compiles dev-dependencies; nothing it alone
        // holds is publishable, and the phase contributes nothing.
        let (packages, lib_packages) = closure_packages(
            &task(),
            &[
                phase(
                    CargoSubcommand::Build,
                    vec![unit("demo", "1.0.0", TaskUnitKind::Lib)],
                ),
                phase(
                    CargoSubcommand::Test,
                    vec![
                        unit("demo", "1.0.0", TaskUnitKind::Lib),
                        unit("devdep", "3.0.0", TaskUnitKind::Lib),
                    ],
                ),
            ],
        )
        .unwrap();
        assert!(!packages.contains(&pair("devdep", "3.0.0")));
        assert!(!lib_packages.contains(&pair("devdep", "3.0.0")));
    }

    #[test]
    fn a_path_package_is_outside_the_closure() {
        // The wrapper is the publisher's own scaffolding: its units compile
        // like the rest of the graph but no registry ever served them, so
        // they belong in no closure.
        let (packages, lib_packages) = closure_packages(
            &task(),
            &[phase(
                CargoSubcommand::Build,
                vec![
                    path_unit("stow-ci-wrapper", "0.0.0"),
                    unit("demo", "1.0.0", TaskUnitKind::Lib),
                ],
            )],
        )
        .unwrap();
        assert!(!packages.contains(&pair("stow-ci-wrapper", "0.0.0")));
        assert!(!lib_packages.contains(&pair("stow-ci-wrapper", "0.0.0")));
    }

    /// The stow#726 shape stated on units: `derive_more-impl 2.1.1`
    /// publishes `build = false` beside `[build-dependencies]
    /// rustc_version`, so cargo plans no unit for `rustc_version` at all —
    /// the graphs hold `derive_more` and `derive_more-impl` and the closure
    /// demands neither an artifact for, nor publishes, `rustc_version`.
    #[test]
    fn a_package_no_unit_graph_holds_is_not_demanded() {
        let (packages, lib_packages) = closure_packages(
            &task(),
            &[
                phase(
                    CargoSubcommand::Check,
                    vec![
                        unit("derive_more", "2.1.1", TaskUnitKind::Lib),
                        unit("derive_more-impl", "2.1.1", TaskUnitKind::Lib),
                        unit("demo", "1.0.0", TaskUnitKind::Lib),
                    ],
                ),
                phase(
                    CargoSubcommand::Build,
                    vec![
                        unit("derive_more", "2.1.1", TaskUnitKind::Lib),
                        unit("derive_more-impl", "2.1.1", TaskUnitKind::Lib),
                        unit("demo", "1.0.0", TaskUnitKind::Lib),
                    ],
                ),
            ],
        )
        .unwrap();
        let rustc_version = pair("rustc_version", "0.4.1");
        assert!(!packages.contains(&rustc_version));
        assert!(!lib_packages.contains(&rustc_version));
        assert!(lib_packages.contains(&pair("derive_more", "2.1.1")));
        assert!(lib_packages.contains(&pair("derive_more-impl", "2.1.1")));
    }

    #[test]
    fn a_closure_without_the_task_crate_is_an_error() {
        // The task crate always resolves as the wrapper's registry
        // dependency; a graph without it is not this task's compilation.
        let error = closure_packages(
            &task(),
            &[phase(
                CargoSubcommand::Build,
                vec![unit("helper", "2.0.0", TaskUnitKind::Lib)],
            )],
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not contain the task crate"),
            "{error}"
        );
    }
}
