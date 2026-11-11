//! What one task's node must publish, and the check that a record set holds
//! it.
//!
//! A node is its crate's library units and its crate's build script. The
//! library shapes are the scheduler's own rule, `required_unit_shapes`: it
//! counts the node complete only once the slice carries them. The build
//! script has no scheduler rule: it is an output of the node, read only by
//! an exact `c_metadata` lookup, so the only evidence of which spellings it
//! must be published under is the cargo unit graphs of the phases the
//! builder ran — a native node whose build-dependencies key apart per
//! spelling compiles its script twice, at two keys, and a consumer building
//! under the other spelling asks for the key the node never published.
//!
//! The same rule judges the publisher's plan (with the graphs it computed
//! itself) and the records an earlier run already published (where no graph
//! exists, so the spellings come from the task's phases).

use std::collections::{BTreeMap, BTreeSet};

use stow_types::api::BuildTaskPayload;
use stow_types::public_cache::{
    UnitInvocation, UnitKind, UnitShape, UnitSide, required_unit_shapes,
};
use stow_types::unit_graph::{TaskUnit, TaskUnitKind};

use crate::task::{self, CargoSubcommand};

/// One shape a node's record set evidences: what kind of output carries it,
/// the shape, and the compile identity it was published under.
#[derive(Debug, Clone)]
pub struct Evidence {
    /// Whether the output is the crate's build script, not a library.
    pub script: bool,
    /// The shape the output serves.
    pub shape: UnitShape,
    /// The output's stable `c_metadata`.
    pub c_metadata: String,
}

/// The build script's shape under one invocation spelling: always a linked
/// host executable.
const fn script_shape(invocation: UnitInvocation) -> UnitShape {
    UnitShape {
        side: UnitSide::Host,
        invocation,
        kind: UnitKind::Linked,
    }
}

/// Every shape the task's own node publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnNodeShapes {
    library: Vec<UnitShape>,
    /// The spellings the build script is owed under, each with the clause
    /// naming what compiles it there.
    scripts: BTreeMap<UnitInvocation, String>,
    /// Whether the publisher's graphs state the crate's script outright: an
    /// empty `scripts` then means the crate owns none, so an own script is
    /// refused. Without graphs (a published record set) a crate with a
    /// script owes it under every spelling of `scripts`, and one without
    /// owes nothing.
    scripts_known: bool,
}

impl OwnNodeShapes {
    /// The shapes from the phase×invocation unit graphs the publisher
    /// computed: a spelling's script is required when a `check` or `build`
    /// graph of that spelling holds a build-script compile unit the task's
    /// own library unit reaches through its run-build-script edge, matched
    /// by package id — never by crate name. A `test` graph holds
    /// dev-dependency units the closure never publishes, so it names
    /// nothing.
    ///
    /// # Errors
    /// Returns an error when a graph does not convert or names no own unit.
    pub fn from_graphs(
        task: &BuildTaskPayload,
        graphs: &[task::PhaseUnitGraph],
    ) -> stow_types::error::Result<Self> {
        let host_triple = task::runner_host_triple(task)?;
        let mut scripts = BTreeMap::new();
        for graph in graphs
            .iter()
            .filter(|graph| graph.phase() != CargoSubcommand::Test)
        {
            let units = graph.task_units(host_triple).map_err(|error| {
                stow_types::stow_error!("{} unit graph does not convert: {error}", graph.label())
            })?;
            let own = crate::dep_scan::own_lib_unit(task, &graph.label(), &units)?;
            if own_build_scripts(own, &units).next().is_some() {
                let invocation = if graph.target().is_some() {
                    UnitInvocation::Target
                } else {
                    UnitInvocation::Native
                };
                scripts
                    .entry(invocation)
                    .or_insert_with(|| script_clause(&graph.label()));
            }
        }
        Ok(Self {
            library: library_shapes(task)?,
            scripts,
            scripts_known: true,
        })
    }

    /// The shapes of a task with no unit graph at hand: the library rule,
    /// and — when the record set carries a script of the crate — every
    /// spelling the task's phases use (a native triple runs the native and
    /// the explicit `--target` spelling, a cross triple only the latter).
    ///
    /// # Errors
    /// Returns an error when no runner family builds the task's target.
    pub fn from_phases(task: &BuildTaskPayload) -> stow_types::error::Result<Self> {
        let spellings: &[UnitInvocation] =
            if task::runner_host_triple(task)? == task.target.as_str() {
                &[UnitInvocation::Native, UnitInvocation::Target]
            } else {
                &[UnitInvocation::Target]
            };
        Ok(Self {
            library: library_shapes(task)?,
            scripts: spellings
                .iter()
                .map(|&invocation| {
                    (
                        invocation,
                        "the task's phases compile its build script".to_owned(),
                    )
                })
                .collect(),
            scripts_known: false,
        })
    }

    /// Shapes stated outright, for tests: a script under each spelling,
    /// compiled by the unit graph the label names.
    #[cfg(test)]
    pub fn new(library: Vec<UnitShape>, scripts: &[(UnitInvocation, &str)]) -> Self {
        Self {
            library,
            scripts: scripts
                .iter()
                .map(|&(invocation, label)| (invocation, script_clause(label)))
                .collect(),
            scripts_known: true,
        }
    }

    /// The library shapes the node owes, for tests.
    #[cfg(test)]
    pub fn library(&self) -> &[UnitShape] {
        &self.library
    }

    /// The spellings the build script is owed under and the clause naming
    /// the graph that compiles it, for tests.
    #[cfg(test)]
    pub const fn script_clauses(&self) -> &BTreeMap<UnitInvocation, String> {
        &self.scripts
    }

    /// The first shape `evidence` fails to cover, or an own script no phase
    /// compiles; `None` when the record set holds the whole node.
    #[must_use]
    pub fn gap(&self, evidence: &[Evidence]) -> Option<ShapeGap> {
        let (scripts, libraries): (Vec<Evidence>, Vec<Evidence>) =
            evidence.iter().cloned().partition(|item| item.script);
        if let Some(&missing) = self
            .library
            .iter()
            .find(|shape| !libraries.iter().any(|item| item.shape == **shape))
        {
            return Some(ShapeGap::Library {
                missing,
                covered: shapes_of(&libraries),
            });
        }
        if !self.scripts_known && scripts.is_empty() {
            return None;
        }
        let covered = shapes_of(&scripts);
        if let Some((&invocation, compiled_by)) = self
            .scripts
            .iter()
            .find(|&(&invocation, _)| !covered.contains(&script_shape(invocation)))
        {
            return Some(ShapeGap::Script {
                missing: script_shape(invocation),
                compiled_by: compiled_by.clone(),
                covered,
                c_metadata: scripts.iter().map(|item| item.c_metadata.clone()).collect(),
            });
        }
        scripts
            .iter()
            .find(|item| {
                !self.scripts.contains_key(&item.shape.invocation)
                    || item.shape != script_shape(item.shape.invocation)
            })
            .map(|item| ShapeGap::ScriptNotCompiled {
                shape: item.shape,
                c_metadata: item.c_metadata.clone(),
            })
    }
}

/// What names the phase that compiles a build script in a refusal.
fn script_clause(graph_label: &str) -> String {
    format!("the publisher's \"{graph_label}\" unit graph compiles its build script")
}

/// The library shapes the scheduler counts the node complete on.
fn library_shapes(task: &BuildTaskPayload) -> stow_types::error::Result<Vec<UnitShape>> {
    let invocation =
        UnitInvocation::for_task(task.target.as_str(), task::runner_host_triple(task)?);
    Ok(required_unit_shapes(
        task.host_side,
        invocation,
        task.explicit_spelling,
    ))
}

/// The build-script compile units `own`'s run-build-script edge reaches in
/// one graph's `units`, matched by package id.
fn own_build_scripts<'u>(
    own: &'u TaskUnit,
    units: &'u [TaskUnit],
) -> impl Iterator<Item = &'u TaskUnit> {
    let find =
        move |key: &stow_types::unit_graph::TaskUnitKey| units.iter().find(|unit| unit.key == *key);
    own.deps
        .iter()
        .filter(|dep| dep.key.kind == TaskUnitKind::RunBuildScript)
        .filter_map(move |dep| find(&dep.key))
        .flat_map(|run| &run.deps)
        .filter(|dep| dep.key.kind == TaskUnitKind::BuildScript)
        .filter_map(move |dep| find(&dep.key))
        .filter(|script| script.key.pkg == own.key.pkg)
}

fn shapes_of(evidence: &[Evidence]) -> BTreeSet<UnitShape> {
    evidence.iter().map(|item| item.shape).collect()
}

/// A shape the node owes and its record set does not hold, or an output the
/// phases never compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShapeGap {
    /// A library shape the scheduler's rule requires is missing.
    Library {
        missing: UnitShape,
        covered: BTreeSet<UnitShape>,
    },
    /// A build-script shape a phase compiles is missing.
    Script {
        missing: UnitShape,
        compiled_by: String,
        covered: BTreeSet<UnitShape>,
        c_metadata: BTreeSet<String>,
    },
    /// An own build script no phase of the task compiles.
    ScriptNotCompiled {
        shape: UnitShape,
        c_metadata: String,
    },
}

/// `side/invocation/kind`, the way the shapes are written everywhere else.
fn shape_name(shape: UnitShape) -> String {
    let side = match shape.side {
        UnitSide::Host => "host",
        UnitSide::Target => "target",
    };
    let invocation = match shape.invocation {
        UnitInvocation::Native => "native",
        UnitInvocation::Target => "target",
    };
    let kind = match shape.kind {
        UnitKind::Linked => "linked",
        UnitKind::Unlinked => "unlinked",
    };
    format!("{side}/{invocation}/{kind}")
}

fn shape_list(shapes: &BTreeSet<UnitShape>) -> String {
    shapes
        .iter()
        .map(|&shape| shape_name(shape))
        .collect::<Vec<_>>()
        .join(", ")
}

impl ShapeGap {
    /// The refusal text: names the task, the shape it lacks, what compiles
    /// that shape and what the `source` (`the plan`, `the published
    /// records`) did cover.
    #[must_use]
    pub fn refusal(&self, task: &BuildTaskPayload, source: &str) -> String {
        let possessive = if source.ends_with('s') {
            format!("{source}'")
        } else {
            format!("{source}'s")
        };
        let node = format!(
            "task {} ({} {} {}, {} side of {})",
            task.task_id,
            task.crate_name,
            task.version,
            task.features_json.raw(),
            if task.host_side { "host" } else { "target" },
            task.target,
        );
        match self {
            Self::Library { missing, covered } => format!(
                "{node} lacks library shape {}: the scheduler requires it of the node, but {possessive} library artifacts cover {}",
                shape_name(*missing),
                if covered.is_empty() {
                    "none".to_owned()
                } else {
                    format!("only {}", shape_list(covered))
                },
            ),
            Self::Script {
                missing,
                compiled_by,
                covered,
                c_metadata,
            } => format!(
                "{node} lacks build-script shape {}: {compiled_by}, but {possessive} build scripts {}",
                shape_name(*missing),
                if covered.is_empty() {
                    "hold none".to_owned()
                } else {
                    format!(
                        "cover only {} (c_metadata {})",
                        shape_list(covered),
                        c_metadata.iter().cloned().collect::<Vec<_>>().join(", ")
                    )
                },
            ),
            Self::ScriptNotCompiled { shape, c_metadata } => format!(
                "{node} carries a build script at shape {} that no phase of the task compiles (c_metadata {c_metadata}): {source} holds a unit the publisher's own unit graphs do not",
                shape_name(*shape),
            ),
        }
    }
}

/// The evidence one published records artifact holds for `task`'s node:
/// every record of the task's own crate, and every completed local program
/// (which stands for the library shape it carries).
#[must_use]
pub fn record_evidence(
    task: &BuildTaskPayload,
    records: &stow_types::records::BuildRecords,
) -> Vec<Evidence> {
    records
        .artifacts
        .iter()
        .filter(|record| {
            record.crate_name == task.crate_name
                && record.version.as_semver() == task.version.as_semver()
        })
        .map(|record| Evidence {
            script: record.artifact_kind == stow_types::artifact::ArtifactKind::BuildScript,
            shape: record.unit_shape,
            c_metadata: record.c_metadata.to_string(),
        })
        .chain(records.local_programs.iter().map(|program| Evidence {
            script: false,
            shape: program.unit_shape,
            c_metadata: program.c_metadata.to_string(),
        }))
        .collect()
}

/// Whether a published `records` artifact holds the whole node of `task`:
/// the library shapes the scheduler requires and, when the crate's build
/// script is among the records, that script under every spelling the
/// task's phases use. A record set that does not is no proof the node is
/// published.
///
/// # Errors
/// Returns an error when no runner family builds the task's target.
pub fn published_records_gap(
    task: &BuildTaskPayload,
    records: &stow_types::records::BuildRecords,
) -> stow_types::error::Result<Option<ShapeGap>> {
    Ok(OwnNodeShapes::from_phases(task)?.gap(&record_evidence(task, records)))
}

#[cfg(test)]
mod tests {
    use stow_types::public_cache::{
        ExplicitSpelling, UnitInvocation, UnitKind, UnitShape, UnitSide, required_unit_shapes,
    };

    use super::{Evidence, OwnNodeShapes, ShapeGap, script_shape};

    fn shape(side: UnitSide, invocation: UnitInvocation, kind: UnitKind) -> UnitShape {
        UnitShape {
            side,
            invocation,
            kind,
        }
    }

    fn library_evidence(shapes: &[UnitShape]) -> Vec<Evidence> {
        shapes
            .iter()
            .map(|&shape| Evidence {
                script: false,
                shape,
                c_metadata: "0123456789abcdef".to_owned(),
            })
            .collect()
    }

    fn script_evidence(invocations: &[UnitInvocation]) -> Vec<Evidence> {
        invocations
            .iter()
            .map(|&invocation| Evidence {
                script: true,
                shape: script_shape(invocation),
                c_metadata: "22aac6cb837ae789".to_owned(),
            })
            .collect()
    }

    /// A task class: its name, whether it is host side, its own
    /// invocation, its explicit spelling, the library shapes the scheduler
    /// requires of it, and the spellings its build script is compiled
    /// under.
    type Class = (
        &'static str,
        bool,
        UnitInvocation,
        ExplicitSpelling,
        Vec<UnitShape>,
        Vec<UnitInvocation>,
    );

    /// The four task classes.
    fn classes() -> [Class; 4] {
        use UnitInvocation::{Native, Target};
        use UnitKind::{Linked, Unlinked};
        use UnitSide::{Host, Target as TargetSide};
        [
            (
                "host side",
                true,
                Native,
                ExplicitSpelling::KeysAsNative,
                vec![shape(Host, Native, Linked), shape(Host, Target, Linked)],
                vec![Native, Target],
            ),
            (
                "target side, native, keys apart",
                false,
                Native,
                ExplicitSpelling::KeysApart,
                vec![
                    shape(TargetSide, Native, Unlinked),
                    shape(TargetSide, Native, Linked),
                    shape(TargetSide, Target, Unlinked),
                    shape(TargetSide, Target, Linked),
                ],
                vec![Native, Target],
            ),
            (
                "target side, native, keys as native",
                false,
                Native,
                ExplicitSpelling::KeysAsNative,
                vec![
                    shape(TargetSide, Native, Unlinked),
                    shape(TargetSide, Native, Linked),
                ],
                vec![Native, Target],
            ),
            (
                "target side, cross",
                false,
                Target,
                ExplicitSpelling::KeysAsNative,
                vec![
                    shape(TargetSide, Target, Unlinked),
                    shape(TargetSide, Target, Linked),
                ],
                vec![Target],
            ),
        ]
    }

    /// The library rule is the scheduler's, whatever the class.
    #[test]
    fn the_library_shapes_follow_the_task_class() {
        for (class, host_side, invocation, spelling, library, _) in classes() {
            assert_eq!(
                required_unit_shapes(host_side, invocation, spelling),
                library,
                "{class}: the library rule"
            );
        }
    }

    /// Each class, with and without an own build script, owes exactly the
    /// library shapes of the rule and the script spellings its phase
    /// graphs compile it under.
    #[test]
    fn a_node_owes_the_shapes_of_its_class() {
        for (class, _, _, _, library, scripts) in classes() {
            let clause = "check phase";
            let with_script = OwnNodeShapes::new(
                library.clone(),
                &scripts
                    .iter()
                    .map(|&invocation| (invocation, clause))
                    .collect::<Vec<_>>(),
            );
            let without_script = OwnNodeShapes::new(library.clone(), &[]);
            let mut full = library_evidence(&library);
            full.extend(script_evidence(&scripts));
            assert_eq!(
                with_script.gap(&full),
                None,
                "{class}: complete with script"
            );
            assert_eq!(
                without_script.gap(&library_evidence(&library)),
                None,
                "{class}: complete without script"
            );
            // A script the graphs lack is refused.
            assert!(
                matches!(
                    without_script.gap(&full),
                    Some(ShapeGap::ScriptNotCompiled { .. })
                ),
                "{class}: a script no phase compiles"
            );
            // Every script spelling is owed.
            for dropped in &scripts {
                let mut short = library_evidence(&library);
                short.extend(script_evidence(
                    &scripts
                        .iter()
                        .copied()
                        .filter(|invocation| invocation != dropped)
                        .collect::<Vec<_>>(),
                ));
                match with_script.gap(&short) {
                    Some(ShapeGap::Script { missing, .. }) => {
                        assert_eq!(missing, script_shape(*dropped), "{class}");
                    }
                    other => panic!("{class}: dropping {dropped:?} gave {other:?}"),
                }
            }
            // Every library shape is owed.
            for dropped in &library {
                let mut short = library_evidence(
                    &library
                        .iter()
                        .copied()
                        .filter(|kept| kept != dropped)
                        .collect::<Vec<_>>(),
                );
                short.extend(script_evidence(&scripts));
                match with_script.gap(&short) {
                    Some(ShapeGap::Library { missing, covered }) => {
                        assert_eq!(missing, *dropped, "{class}");
                        assert!(!covered.contains(dropped), "{class}");
                    }
                    other => panic!("{class}: dropping {dropped:?} gave {other:?}"),
                }
            }
        }
    }

    /// A script owed only when the records carry one: a published record
    /// set has no graph to say whether the crate owns a script.
    #[test]
    fn a_published_record_set_owes_the_script_it_carries_in_every_spelling() {
        let library = required_unit_shapes(
            false,
            UnitInvocation::Native,
            ExplicitSpelling::KeysAsNative,
        );
        let owed = |spellings: &[UnitInvocation]| OwnNodeShapes {
            library: library.clone(),
            scripts: spellings
                .iter()
                .map(|&invocation| (invocation, "the task's phases".to_owned()))
                .collect(),
            scripts_known: false,
        };
        let native = owed(&[UnitInvocation::Native, UnitInvocation::Target]);
        let mut records = library_evidence(&library);
        assert_eq!(native.gap(&records), None, "no script, none owed");
        records.extend(script_evidence(&[UnitInvocation::Native]));
        assert!(matches!(
            native.gap(&records),
            Some(ShapeGap::Script { missing, .. }) if missing == script_shape(UnitInvocation::Target)
        ));
        records.extend(script_evidence(&[UnitInvocation::Target]));
        assert_eq!(native.gap(&records), None);
        let cross = owed(&[UnitInvocation::Target]);
        assert_eq!(
            cross.gap(&library_evidence(&library)),
            None,
            "no script, none owed"
        );
        let native_only = {
            let mut records = library_evidence(&library);
            records.extend(script_evidence(&[UnitInvocation::Native]));
            records
        };
        assert!(cross.gap(&native_only).is_some());
    }
}
