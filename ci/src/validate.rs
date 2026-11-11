//! Checks the trusted publisher runs on a build job's plan before it touches
//! a credential.
//!
//! The plan was produced next to third-party code. Every identity field in
//! it is therefore a claim, and the publisher only pushes, signs and
//! registers claims it can tie back to something it established itself: the
//! task it was dispatched with and the dependency closure it resolved.

use std::collections::{BTreeMap, BTreeSet};

use stow_cli::build_consume::IndexSlice;
use stow_types::api::BuildTaskPayload;
use stow_types::public_cache::canonical_crate_name;
use stow_types::registry::oci_reference;
use stow_types::upload_plan::PlannedArtifact;

use crate::closure::DependencyClosure;
use crate::dep_scan::ConsumedArtifact;
use crate::plan::planned_artifact_key;

/// A planned artifact belongs to the task's own node, so it carries the
/// profile the task was dispatched with.
fn validate_profile(
    task: &BuildTaskPayload,
    artifact: &PlannedArtifact,
) -> stow_types::error::Result<()> {
    if artifact.node_profile == task.profile {
        return Ok(());
    }
    Err(stow_types::stow_error!(
        "planned artifact {} was built under profile {} but the task requires {}",
        artifact.oci_reference,
        artifact.node_profile,
        task.profile
    ))
}

/// Reject the plan unless every entry — and every cache-consumption claim —
/// belongs to `task`. The build stage only produces output when every phase
/// finished and no foreign unit compiled, so a plan that reaches the
/// publisher is always claimed to cover the whole closure.
///
/// `consumed` names the verified published artifacts the build job says it
/// injected instead of compiling: no rustc ran for them, so they appear in
/// no capture and the plan legitimately drops them. They are still claims
/// the untrusted job made, so each one must (a) name a crate inside the
/// resolved closure — containment does not weaken — and (b) match a row of
/// the signed index the publisher pulled itself, at the exact
/// `(crate, version, compile_key, c_metadata, target)` the claim carries.
/// A claim the index does not vouch for is a dropped compile pretending to
/// be a cache hit, and fails the same way a missing build artifact does.
pub fn validate_plan(
    task: &BuildTaskPayload,
    built_task: &BuildTaskPayload,
    plan: &[PlannedArtifact],
    closure: &DependencyClosure,
    consumed: &[ConsumedArtifact],
    index_slices: &[IndexSlice],
    programs: &crate::dep_scan::ProgramClaims,
) -> stow_types::error::Result<()> {
    if built_task != task {
        return Err(stow_types::stow_error!(
            "build output was produced for task {} but the publisher was dispatched for task {}",
            built_task.task_id,
            task.task_id
        ));
    }

    validate_consumed_claims(task, closure, consumed, index_slices)?;
    validate_program_claims(task, closure, programs, index_slices)?;

    // A task legitimately produces its crate's units on both sides: the
    // target units `cargo` spelled `--target` for, and the host units it
    // spelled none for — build scripts, proc-macro subtrees — which the
    // scan registers under the runner's host triple, the only value their
    // compile keys embed. Anything outside that pair is a target the
    // build could never have compiled for.
    let host_triple = stow_types::api::runner_family(task.target.as_str())
        .map(stow_types::api::RunnerFamily::host_triple);
    let mut references = BTreeMap::<&str, &PlannedArtifact>::new();
    for artifact in plan {
        if artifact.target != task.target && Some(artifact.target.as_str()) != host_triple {
            return Err(stow_types::stow_error!(
                "planned artifact {} targets {} but the task targets {} on a runner hosting {}",
                artifact.oci_reference,
                artifact.target,
                task.target,
                host_triple.unwrap_or("an unknown triple")
            ));
        }
        if artifact.rustc_version != task.rustc_version {
            return Err(stow_types::stow_error!(
                "planned artifact {} was built with rustc {} but the task requires {}",
                artifact.oci_reference,
                artifact.rustc_version,
                task.rustc_version
            ));
        }
        validate_profile(task, artifact)?;
        // stow#588: the digest claim is the claim that matters most —
        // an artifact built under a different dependency context is a
        // different artifact the cache must never serve under this
        // task's id.
        let artifact_identity = artifact.dependency_identity()?;
        if artifact_identity != *closure.dependency_identity() {
            return Err(stow_types::stow_error!(
                "planned artifact {} claims dependency_identity {} but the publisher verified {} for task {}",
                artifact.oci_reference,
                artifact_identity,
                closure.dependency_identity(),
                task.task_id,
            ));
        }
        // stow#611: the task's own node's rows carry the dispatched
        // feature set verbatim — the same set its unit in the build's
        // cargo unit graph resolved and the label consumers look it up
        // by. A row that disagrees is a mislabel the publish must
        // refuse, not a row the index should advertise.
        validate_own_node_features(task, artifact)?;
        if !closure.contains(
            artifact.crate_name.as_str(),
            artifact.crate_version.as_semver(),
        ) {
            return Err(stow_types::stow_error!(
                "planned artifact {} claims crate {} {}, which is not in the resolved closure of {} {} ({} packages)",
                artifact.oci_reference,
                artifact.crate_name,
                artifact.crate_version,
                task.crate_name,
                task.version,
                closure.package_count()
            ));
        }
        let expected_reference = oci_reference(
            &planned_artifact_key(artifact)?,
            artifact.c_metadata.as_str(),
        );
        if artifact.oci_reference != expected_reference {
            return Err(stow_types::stow_error!(
                "planned artifact reference {} does not match the reference its identity produces, {}",
                artifact.oci_reference,
                expected_reference
            ));
        }
        if let Some(previous) = references.insert(artifact.oci_reference.as_str(), artifact) {
            return Err(stow_types::stow_error!(
                "plan contains two artifacts for {} (compile keys {} and {})",
                artifact.oci_reference,
                previous.compile_key,
                artifact.compile_key
            ));
        }
    }

    validate_coverage(task, plan, closure, consumed, programs)
}

fn validate_coverage(
    task: &BuildTaskPayload,
    plan: &[PlannedArtifact],
    closure: &DependencyClosure,
    consumed: &[ConsumedArtifact],
    programs: &crate::dep_scan::ProgramClaims,
) -> stow_types::error::Result<()> {
    // Containment alone lets a strict subset through: a plan that dropped a
    // compiled crate would still satisfy every check above. Every lib
    // package the trusted pipeline compiled must appear with a build-phase
    // (`link` emit) artifact — a check-phase `dep-info,metadata` entry does
    // not carry the rlib the plan exists to ship — or carry an index-vouched
    // `link` consumed claim, which is the same crate already published.
    for (name, version) in closure.lib_packages() {
        let has_build_artifact = plan.iter().any(|artifact| {
            artifact.crate_name.as_str() == name.as_str()
                && artifact.crate_version.as_semver() == version
                && artifact.kind != stow_types::artifact::ArtifactKind::BuildScript
                && artifact.emit.iter().any(|emit| emit == "link")
        }) || consumed.iter().any(|claim| {
            claim.crate_name.as_str() == name.as_str()
                && claim.crate_version == version.to_string()
                && claim.kind != stow_types::artifact::ArtifactKind::BuildScript
                && claim.emit.iter().any(|emit| emit == "link")
        }) || programs.completed.iter().chain(&programs.compiled).any(
            |program| {
                program.node.crate_name.as_str() == name.as_str()
                    && program.node.version.as_semver() == version
                    && program.unit_shape.kind == stow_types::public_cache::UnitKind::Linked
            },
        );
        if !has_build_artifact {
            return Err(stow_types::stow_error!(
                "plan has no build-phase artifact for {} {}, a library package in the resolved closure of {} {}",
                name,
                version,
                task.crate_name,
                task.version
            ));
        }
    }
    Ok(())
}

fn validate_program_claims(
    task: &BuildTaskPayload,
    closure: &DependencyClosure,
    programs: &crate::dep_scan::ProgramClaims,
    slices: &[IndexSlice],
) -> stow_types::error::Result<()> {
    for program in programs.completed.iter().chain(&programs.compiled) {
        if !closure.is_proc_macro(
            program.node.crate_name.as_str(),
            program.node.version.as_semver(),
        ) || !closure.contains(
            program.node.crate_name.as_str(),
            program.node.version.as_semver(),
        ) {
            return Err(stow_types::stow_error!(
                "local program {} is not a proc macro in the verified closure",
                program.node.crate_name
            ));
        }
        if !program.node.host_side
            || program.unit_shape.side != stow_types::public_cache::UnitSide::Host
            || program.unit_shape.kind != stow_types::public_cache::UnitKind::Linked
        {
            return Err(stow_types::stow_error!(
                "local program {} must be a linked host proc macro",
                program.node.crate_name
            ));
        }
        if stow_types::public_cache::stable_c_metadata_for_compile_key(&program.compile_key)?
            != program.c_metadata.as_str()
        {
            return Err(stow_types::stow_error!(
                "local program {} has inconsistent compile identity",
                program.node.crate_name
            ));
        }
    }
    for program in &programs.completed {
        if program.node != task.task_node_identity()
            || program.task_id()? != task.task_id
            || program.dependency_identity()? != *closure.dependency_identity()
        {
            return Err(stow_types::stow_error!(
                "completed local program does not belong to task {}",
                task.task_id
            ));
        }
    }
    if programs.compiled.is_empty() {
        return Ok(());
    }
    let graph = task.verified_dependency_graph()?;
    for program in &programs.compiled {
        let id = program.task_id()?;
        if !(1..graph.nodes().len()).any(|index| graph.task_id(index) == Some(id.as_str()))
            || !slices.iter().any(|slice| {
                slice.index.header.target == program.node.target
                    && slice.index.header.rustc_version == program.node.rustc_version
                    && slice.index.local_programs.contains(program)
            })
        {
            return Err(stow_types::stow_error!(
                "locally compiled program {id} matches no signed dependency declaration"
            ));
        }
    }
    Ok(())
}

/// A row for the dispatched task's own node must carry `task`'s feature
/// set exactly — the feature set the task's unit resolved at, which is
/// the label the row will be looked up by. Anything else (for example
/// the invocation's `--cfg feature="…"` scan, which build-script
/// `cargo:rustc-cfg=feature` output can enter, stow#611) is a mislabel
/// the publish refuses, named by both sets.
fn validate_own_node_features(
    task: &BuildTaskPayload,
    artifact: &PlannedArtifact,
) -> stow_types::error::Result<()> {
    let dispatched_version = task.version.as_semver();
    let own_node = artifact.crate_name == task.crate_name
        && artifact.crate_version.as_semver() == dispatched_version;
    if own_node && artifact.features_json != task.features_json {
        return Err(stow_types::stow_error!(
            "planned artifact {} for the task's own crate {} {} carries features {} but the task dispatched {}",
            artifact.oci_reference,
            artifact.crate_name,
            artifact.crate_version,
            artifact.features_json.raw(),
            task.features_json.raw(),
        ));
    }
    Ok(())
}

/// The publisher-side proof behind every `consumed` claim: each claim
/// names a crate inside the task's resolved closure — containment does not
/// weaken — and matches a row of the signed index the publisher pulled
/// itself, at the exact `(crate, version, compile_key, c_metadata,
/// target)` the claim carries. A claim the index does not vouch for is a
/// dropped compile pretending to be a cache hit, and fails the same way a
/// missing build artifact does.
fn validate_consumed_claims(
    task: &BuildTaskPayload,
    closure: &DependencyClosure,
    consumed: &[ConsumedArtifact],
    index_slices: &[IndexSlice],
) -> stow_types::error::Result<()> {
    let mut seen_compile_keys = BTreeSet::<&str>::new();
    let pinned = if consumed
        .iter()
        .any(|claim| claim.kind != stow_types::artifact::ArtifactKind::BuildScript)
    {
        crate::consume::pinned_dependency_ids(task)?
    } else {
        BTreeSet::new()
    };
    for claim in consumed {
        if !seen_compile_keys.insert(claim.compile_key.as_str()) {
            return Err(stow_types::stow_error!(
                "consumed claims name compile key {} twice",
                claim.compile_key
            ));
        }
        if claim.rustc_version != task.rustc_version.as_str() {
            return Err(stow_types::stow_error!(
                "consumed artifact {} was served under rustc {} but the task requires {}",
                claim.crate_name,
                claim.rustc_version,
                task.rustc_version
            ));
        }
        let claim_version = semver::Version::parse(&claim.crate_version).map_err(|_| {
            stow_types::stow_error!(
                "consumed artifact {} carries an unparseable version {}",
                claim.crate_name,
                claim.crate_version
            )
        })?;
        if !closure.contains(claim.crate_name.as_str(), &claim_version) {
            return Err(stow_types::stow_error!(
                "consumed artifact claims crate {} {}, which is not in the resolved closure of {} {} ({} packages)",
                claim.crate_name,
                claim.crate_version,
                task.crate_name,
                task.version,
                closure.package_count()
            ));
        }
        let vouching: Vec<(&IndexSlice, &stow_types::index::ArtifactIndexRow)> = index_slices
            .iter()
            .filter(|slice| slice.index.header.target.as_str() == claim.target)
            .flat_map(|slice| {
                slice
                    .index
                    .rows
                    .iter()
                    .chain(&slice.index.build_scripts)
                    .map(move |row| (slice, row))
            })
            .filter(|(_, row)| {
                canonical_crate_name(row.crate_name.as_str())
                    == canonical_crate_name(claim.crate_name.as_str())
                    && row.version.as_semver() == &claim_version
                    && row.compile_key == claim.compile_key
                    && row.c_metadata.as_str() == claim.c_metadata
                    // The claim's emit set is untrusted text and it is
                    // what the completeness rule below reads, so it has to
                    // be the published artifact's own. Without this a
                    // claim could name a metadata-only row's compile key
                    // and present it as `link` coverage for a crate whose
                    // rlib the index does not have.
                    && row.emit == claim.emit
                    && row.artifact_kind == claim.kind
            })
            .collect();
        if vouching.is_empty() {
            return Err(stow_types::stow_error!(
                "consumed artifact {} {} (compile_key {}, c_metadata {}, target {}) matches no row of the signed index — a cache hit the index does not vouch for is a dropped compile",
                claim.crate_name,
                claim.crate_version,
                claim.compile_key,
                claim.c_metadata,
                claim.target
            ));
        }
        // A library is served only from a node of the task's pinned
        // subtree (#1415). A compile key records no side, so another
        // node of the same crate can publish the claimed key; the
        // outcome-3 twin is a subtree node like any other (stow#723),
        // and the task's own node never is one — a claim on its own
        // unit means its artifact never compiled, so the plan has
        // nothing to publish. A build script's row names no node side
        // to derive an identity from, so it is vouched by the match
        // alone.
        if claim.kind != stow_types::artifact::ArtifactKind::BuildScript {
            let mut vouched = false;
            for (slice, row) in &vouching {
                vouched |= crate::consume::published_by_pinned_node(&pinned, slice, row)?;
            }
            if !vouched {
                return Err(stow_types::stow_error!(
                    "consumed artifact {} {} (compile_key {}, target {}) is vouched only by rows of nodes outside the pinned dependency subtree of task {} — a unit is served only from a node the task pins, and never from its own",
                    claim.crate_name,
                    claim.crate_version,
                    claim.compile_key,
                    claim.target,
                    task.task_id
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use stow_types::api::BuildTaskPayload;
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::bundle::{ArtifactBundleFile, STOW_RLIB_MEDIA_TYPE};
    use stow_types::identity::{
        CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson, TargetTriple,
        WireRustcVersion,
    };
    use stow_types::platform::{PanicStrategy, Profile};
    use stow_types::registry::oci_reference;
    use stow_types::upload_plan::{PlannedArtifact, PlannedArtifactOutput};

    use super::validate_plan;
    use crate::closure::DependencyClosure;
    use crate::plan::planned_artifact_key;

    #[test]
    fn a_build_script_keeps_its_nodes_features() {
        let task = task();
        let mut script = planned("demo", "1.0.0");
        script.kind = ArtifactKind::BuildScript;
        script.features_json =
            FeaturesJson::canonicalize(vec!["other".to_owned()]).expect("features");
        assert!(super::validate_own_node_features(&task, &script).is_err());
    }

    #[test]
    fn a_build_script_does_not_cover_its_library() {
        let task = task();
        let mut script = planned("demo", "1.0.0");
        script.kind = ArtifactKind::BuildScript;
        script.crate_types = vec![RustCrateType::Bin];
        script.oci_reference = oci_reference(
            &planned_artifact_key(&script).expect("key"),
            script.c_metadata.as_str(),
        );
        let error = validate_plan(
            &task,
            &task,
            &[script],
            &closure(&[("demo", "1.0.0")]),
            &[],
            &[],
            &crate::dep_scan::ProgramClaims::default(),
        )
        .expect_err("a script cannot stand in for the library");
        assert!(
            error.to_string().contains("no build-phase artifact"),
            "{error}"
        );
    }

    #[test]
    fn a_library_cannot_claim_to_be_a_local_proc_macro() {
        let task = task();
        let programs = crate::dep_scan::ProgramClaims {
            completed: vec![stow_types::records::LocalProcMacro {
                node: task.task_node_identity(),
                dependency_task_ids: Vec::new(),
                dependency_c_metadata_json: DependencyCMetadataJson::default(),
                compile_key: "0".repeat(64),
                c_metadata: CMetadata::parse("0000000000000000").unwrap(),
                unit_shape: planned("demo", "1.0.0").unit_shape,
            }],
            compiled: Vec::new(),
        };
        let error = validate_plan(
            &task,
            &task,
            &[],
            &closure(&[("demo", "1.0.0")]),
            &[],
            &[],
            &programs,
        )
        .expect_err("ordinary library cannot omit its artifact");
        assert!(error.to_string().contains("not a proc macro"), "{error}");
    }

    #[test]
    fn a_local_proc_macro_completes_only_as_a_linked_host_program() {
        use stow_types::public_cache::{UnitKind, UnitSide};
        let mut task = task();
        task.host_side = true;
        task.task_id = task
            .task_node_identity()
            .task_id(&stow_types::identity::DependencyIdentity::leaf().unwrap());
        let packages = BTreeSet::from([("demo".to_owned(), semver::Version::new(1, 0, 0))]);
        let closure =
            DependencyClosure::from_packages(packages.clone(), packages.clone(), packages);
        let compile_key = "0".repeat(64);
        let mut shape = planned("demo", "1.0.0").unit_shape;
        shape.side = UnitSide::Host;
        let mut programs = crate::dep_scan::ProgramClaims {
            completed: vec![stow_types::records::LocalProcMacro {
                node: task.task_node_identity(),
                dependency_task_ids: Vec::new(),
                dependency_c_metadata_json: DependencyCMetadataJson::default(),
                c_metadata: CMetadata::parse(
                    stow_types::public_cache::stable_c_metadata_for_compile_key(&compile_key)
                        .unwrap(),
                )
                .unwrap(),
                compile_key,
                unit_shape: shape,
            }],
            compiled: Vec::new(),
        };
        validate_plan(&task, &task, &[], &closure, &[], &[], &programs)
            .expect("completed host macro needs no downloadable bundle");
        programs.completed[0].unit_shape.side = UnitSide::Target;
        assert!(
            validate_plan(&task, &task, &[], &closure, &[], &[], &programs)
                .unwrap_err()
                .to_string()
                .contains("linked host proc macro")
        );
        programs.completed[0].unit_shape.side = UnitSide::Host;
        programs.completed[0].unit_shape.kind = UnitKind::Unlinked;
        assert!(
            validate_plan(&task, &task, &[], &closure, &[], &[], &programs)
                .unwrap_err()
                .to_string()
                .contains("linked host proc macro")
        );
    }

    #[test]
    fn a_signed_own_script_is_consumable_but_never_covers_the_library() {
        let task = task();
        let library = planned("demo", "1.0.0");
        let row = stow_types::index::ArtifactIndexRow {
            crate_name: library.crate_name.clone(),
            version: library.crate_version.clone(),
            features_json: library.features_json.clone(),
            dependency_c_metadata_json: library.dependency_c_metadata_json.clone(),
            dependency_task_ids: library.dependency_task_ids.clone(),
            c_metadata: library.c_metadata.clone(),
            compile_key: library.compile_key.clone(),
            bundle_digest: format!("sha256:{}", "0".repeat(64)),
            bundle_size: 4,
            artifact_kind: ArtifactKind::BuildScript,
            crate_types: vec![RustCrateType::Bin],
            profile: library.profile.clone(),
            node_profile: library.node_profile,
            emit: library.emit.clone(),
            unit_shape: stow_types::public_cache::UnitShape {
                side: stow_types::public_cache::UnitSide::Host,
                invocation: stow_types::public_cache::UnitInvocation::Native,
                kind: stow_types::public_cache::UnitKind::Linked,
            },
            min_glibc: None,
        };
        let claim = crate::dep_scan::ConsumedArtifact {
            kind: ArtifactKind::BuildScript,
            crate_name: task.crate_name.to_string(),
            crate_version: task.version.to_string(),
            compile_key: row.compile_key.clone(),
            c_metadata: row.c_metadata.to_string(),
            target: task.target.to_string(),
            rustc_version: task.rustc_version.to_string(),
            emit: row.emit.clone(),
        };
        let slices = [stow_cli::build_consume::IndexSlice {
            manifest_digest: Some(format!("sha256:{}", "1".repeat(64))),
            index: stow_types::index::ArtifactIndex {
                header: stow_types::index::ArtifactIndexHeader {
                    format_version: stow_types::index::ARTIFACT_INDEX_FORMAT_VERSION,
                    target: task.target.clone(),
                    rustc_version: task.rustc_version.clone(),
                    generated_at: String::new(),
                    generation: 1,
                    row_count: 0,
                },
                rows: Vec::new(),
                build_scripts: vec![row],
                local_programs: Vec::new(),
            },
        }];
        let closure = closure(&[("demo", "1.0.0")]);
        let programs = crate::dep_scan::ProgramClaims::default();
        let claims = [claim];
        validate_plan(
            &task,
            &task,
            &[library],
            &closure,
            &claims,
            &slices,
            &programs,
        )
        .expect("own script can be served while the library compiles");
        let error = validate_plan(&task, &task, &[], &closure, &claims, &slices, &programs)
            .expect_err("a script alone does not complete the library");
        assert!(
            error.to_string().contains("no build-phase artifact"),
            "{error}"
        );
    }

    /// The claim a build makes for having been served `row`.
    fn claim_for(row: &stow_types::index::ArtifactIndexRow) -> crate::dep_scan::ConsumedArtifact {
        crate::dep_scan::ConsumedArtifact {
            kind: row.artifact_kind.clone(),
            crate_name: row.crate_name.to_string(),
            crate_version: row.version.to_string(),
            compile_key: row.compile_key.clone(),
            c_metadata: row.c_metadata.to_string(),
            target: crate::consume::test_support::SLICE_TARGET.to_owned(),
            rustc_version: "1.99.0".to_owned(),
            emit: row.emit.clone(),
        }
    }

    /// #1415 result A: the pinned twin's unit is claimed and the twin's own
    /// row vouches for it, although unrelated host and target nodes of the
    /// same crate published the same compile key.
    #[test]
    fn a_pinned_twins_claim_stands_beside_other_nodes_rows_at_its_key() {
        use crate::consume::test_support::{
            index_slice, itoa_row, serde_row, twin_row, twinned_host_task,
        };
        use stow_types::public_cache::UnitSide;
        let task = twinned_host_task();
        let slices = [index_slice(vec![
            itoa_row(),
            twin_row(),
            serde_row(UnitSide::Host, vec!["itoa-1.0.17-unpinned".to_owned()]),
            serde_row(UnitSide::Target, vec!["bytes-1.11.0-unpinned".to_owned()]),
        ])];
        let closure = closure(&[("serde", "1.0.229"), ("itoa", "1.0.18")]);
        super::validate_consumed_claims(
            &task,
            &closure,
            &[claim_for(&twin_row()), claim_for(&itoa_row())],
            &slices,
        )
        .expect("a claim vouched by a node of the pinned subtree stands");
    }

    /// #1415 result B: the task's own unit's key, published by a target
    /// node the task does not pin, vouches for nothing — and the task's
    /// own published row cannot be claimed either.
    #[test]
    fn a_claim_vouched_only_by_nodes_outside_the_subtree_is_rejected() {
        use crate::consume::test_support::{
            index_slice, itoa_row, own_row, serde_row, twinned_host_task,
        };
        use stow_types::public_cache::UnitSide;
        let task = twinned_host_task();
        let closure = closure(&[("serde", "1.0.229"), ("itoa", "1.0.18")]);

        let unpinned = serde_row(UnitSide::Target, vec!["bytes-1.11.0-unpinned".to_owned()]);
        let slices = [index_slice(vec![itoa_row(), unpinned.clone()])];
        let error =
            super::validate_consumed_claims(&task, &closure, &[claim_for(&unpinned)], &slices)
                .expect_err("a row of a node the task does not pin cannot vouch");
        assert!(
            error
                .to_string()
                .contains("outside the pinned dependency subtree"),
            "{error}"
        );

        let own = own_row();
        let slices = [index_slice(vec![itoa_row(), own.clone()])];
        let error = super::validate_consumed_claims(&task, &closure, &[claim_for(&own)], &slices)
            .expect_err("the task's own unit is never served to it");
        assert!(
            error
                .to_string()
                .contains("outside the pinned dependency subtree"),
            "{error}"
        );
    }

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
            profile: stow_types::node_profile::NodeProfile::Dev,
        }
    }

    fn closure(packages: &[(&str, &str)]) -> DependencyClosure {
        closure_with_libs(packages, packages)
    }

    fn closure_with_libs(
        packages: &[(&str, &str)],
        lib_packages: &[(&str, &str)],
    ) -> DependencyClosure {
        let to_set = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(name, version)| {
                    ((*name).to_owned(), semver::Version::parse(version).unwrap())
                })
                .collect::<BTreeSet<_>>()
        };
        DependencyClosure::from_packages(to_set(packages), to_set(lib_packages), BTreeSet::new())
    }

    #[test]
    fn shared_host_plan_publishes_both_shapes_from_one_bundle() {
        use stow_types::public_cache::{UnitInvocation, UnitKind, UnitShape, UnitSide};
        let mut plan = planned("demo", "1.0.0");
        plan.unit_shape = UnitShape {
            side: UnitSide::Host,
            invocation: UnitInvocation::Native,
            kind: UnitKind::Linked,
        };
        plan.shared_invocations = true;
        plan.node_profile = stow_types::node_profile::NodeProfile::Release;
        let published = stow_types::upload_plan::PublishedArtifact {
            oci_digest: format!("sha256:{}", "a".repeat(64)),
            bundle_digest: format!("sha256:{}", "b".repeat(64)),
            bundle_size: 123,
        };
        let coordinates =
            std::collections::BTreeMap::from([(plan.oci_reference.clone(), published.clone())]);
        let floors = std::collections::BTreeMap::from([(plan.oci_reference.clone(), None)]);
        let records =
            stow_types::upload_plan::build_artifact_records(&[plan], &coordinates, &floors)
                .expect("shared records");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].unit_shape.invocation, UnitInvocation::Native);
        assert_eq!(records[1].unit_shape.invocation, UnitInvocation::Target);
        for record in &records {
            assert_eq!(record.compile_key, records[0].compile_key);
            assert_eq!(record.bundle_digest, published.bundle_digest);
            assert_eq!(
                record.node_profile,
                stow_types::node_profile::NodeProfile::Release
            );
        }
    }

    fn planned(crate_name: &str, version: &str) -> PlannedArtifact {
        let mut artifact = PlannedArtifact {
            shared_invocations: false,
            dependency_task_ids: Vec::new(),
            compile_key: "0".repeat(64),
            crate_name: CrateName::parse(crate_name).unwrap(),
            crate_version: CrateVersion::new(semver::Version::parse(version).unwrap()),
            c_metadata: CMetadata::parse("0123456789abcdef").unwrap(),
            extra_filename: "-0123456789abcdef".to_owned(),
            features_json: FeaturesJson::default(),
            dependency_c_metadata_json: DependencyCMetadataJson::default(),
            dependency_compile_keys_json: "[]".to_owned(),
            unit_shape: stow_types::public_cache::UnitShape {
                side: stow_types::public_cache::UnitSide::Target,
                invocation: stow_types::public_cache::UnitInvocation::Native,
                kind: stow_types::public_cache::UnitKind::Linked,
            },
            target: TargetTriple::parse("x86_64-unknown-linux-gnu").unwrap(),
            rustc_version: WireRustcVersion::parse("1.91.1").unwrap(),
            profile: Profile {
                opt_level: "0".to_owned(),
                debuginfo: 0,
                debug_assertions: true,
                overflow_checks: true,
                panic: PanicStrategy::Unwind,
                strip: stow_types::platform::StripLevel::None,
            },
            emit: vec!["link".to_owned()],
            oci_reference: String::new(),
            kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Lib],
            artifact_size: 4,
            compile_millis: 0,
            outputs: vec![PlannedArtifactOutput {
                path: "blobs/x".into(),
                bundle_file: ArtifactBundleFile {
                    file_name: format!("lib{crate_name}.rlib"),
                    media_type: STOW_RLIB_MEDIA_TYPE.to_owned(),
                    sha256: "0".repeat(64),
                },
            }],
            native: None,
            native_archive: None,
            node_profile: stow_types::node_profile::NodeProfile::Dev,
        };
        artifact.oci_reference = oci_reference(
            &planned_artifact_key(&artifact).unwrap(),
            artifact.c_metadata.as_str(),
        );
        artifact
    }

    #[test]
    fn accepts_plan_inside_closure() {
        let plan = vec![planned("demo", "1.0.0"), planned("serde", "1.0.210")];
        validate_plan(
            &task(),
            &task(),
            &plan,
            &closure(&[("demo", "1.0.0"), ("serde", "1.0.210")]),
            &[],
            &[],
            &crate::dep_scan::ProgramClaims::default(),
        )
        .unwrap();
    }

    /// stow#588: a plan claiming a dependency identity other than the
    /// one the publisher verified is a different artifact — reject it.
    #[test]
    fn rejects_a_plan_whose_dependency_identity_differs() {
        let mut artifact = planned("demo", "1.0.0");
        artifact.dependency_task_ids = vec!["foreign-dep-1.0.0-x".to_owned()];
        let error = validate_plan(
            &task(),
            &task(),
            &[artifact],
            &closure(&[("demo", "1.0.0")]),
            &[],
            &[],
            &crate::dep_scan::ProgramClaims::default(),
        )
        .unwrap_err();
        assert!(
            format!("{error}").contains("dependency_identity"),
            "the rejection names the differing claim: {error}"
        );
    }

    /// stow#611: a row for the task's own crate must carry the dispatched
    /// feature set exactly — the set its unit resolved and consumers
    /// compute. A row labelled with the invocation's `--cfg feature` scan
    /// (a build script's `cargo:rustc-cfg=feature` output included) is a
    /// mislabel the publish refuses, naming both sets.
    #[test]
    fn rejects_an_own_node_row_whose_features_differ_from_the_task() {
        let mut artifact = planned("demo", "1.0.0");
        artifact.features_json =
            FeaturesJson::canonicalize(vec!["default".to_owned(), "rust_1_40".to_owned()]).unwrap();
        artifact.oci_reference = oci_reference(
            &planned_artifact_key(&artifact).unwrap(),
            artifact.c_metadata.as_str(),
        );
        let error = validate_plan(
            &task(),
            &task(),
            &[artifact],
            &closure(&[("demo", "1.0.0")]),
            &[],
            &[],
            &crate::dep_scan::ProgramClaims::default(),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("[\"default\",\"rust_1_40\"]"), "{message}");
        assert!(message.contains("task dispatched []"), "{message}");
    }

    #[test]
    fn rejects_crate_outside_closure() {
        let plan = vec![planned("demo", "1.0.0"), planned("serde", "1.0.210")];
        let error = validate_plan(
            &task(),
            &task(),
            &plan,
            &closure(&[("demo", "1.0.0")]),
            &[],
            &[],
            &crate::dep_scan::ProgramClaims::default(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("not in the resolved closure"),
            "{error}"
        );
    }

    /// A task's own host units — build scripts, proc-macro subtrees —
    /// carry no `--target` and register under the runner's host triple,
    /// the only value their compile keys embed; the task target and the
    /// runner host are the two targets a plan may name.
    #[test]
    fn accepts_a_host_unit_registered_under_the_runner_host() {
        let mut task = task();
        task.target = TargetTriple::parse("aarch64-unknown-linux-gnu").unwrap();
        let mut host_unit = planned("demo", "1.0.0");
        host_unit.target = TargetTriple::parse("x86_64-unknown-linux-gnu").unwrap();
        host_unit.oci_reference = oci_reference(
            &planned_artifact_key(&host_unit).unwrap(),
            host_unit.c_metadata.as_str(),
        );
        validate_plan(
            &task,
            &task,
            &[host_unit],
            &closure(&[("demo", "1.0.0")]),
            &[],
            &[],
            &crate::dep_scan::ProgramClaims::default(),
        )
        .unwrap();
    }

    /// A host unit keyed under a host other than the runner's — what a
    /// build on the wrong machine produces, and what the mock compiler's
    /// runner emulation exists to avoid — is refused, never published
    /// under the task's runner.
    #[test]
    fn rejects_a_host_unit_from_another_runner_host() {
        let mut task = task();
        task.target = TargetTriple::parse("x86_64-unknown-linux-gnu").unwrap();
        let mut host_unit = planned("demo", "1.0.0");
        host_unit.target = TargetTriple::parse("aarch64-apple-darwin").unwrap();
        host_unit.oci_reference = oci_reference(
            &planned_artifact_key(&host_unit).unwrap(),
            host_unit.c_metadata.as_str(),
        );
        let error = validate_plan(
            &task,
            &task,
            &[host_unit],
            &closure(&[("demo", "1.0.0")]),
            &[],
            &[],
            &crate::dep_scan::ProgramClaims::default(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains(
                "targets aarch64-apple-darwin but the task targets x86_64-unknown-linux-gnu \
                 on a runner hosting x86_64-unknown-linux-gnu"
            ),
            "{error}"
        );
    }

    #[test]
    fn rejects_foreign_target_and_rustc() {
        let mut other_target = planned("demo", "1.0.0");
        other_target.target = TargetTriple::parse("aarch64-apple-darwin").unwrap();
        let error = validate_plan(
            &task(),
            &task(),
            &[other_target],
            &closure(&[("demo", "1.0.0")]),
            &[],
            &[],
            &crate::dep_scan::ProgramClaims::default(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("targets aarch64-apple-darwin"),
            "{error}"
        );

        let mut other_rustc = planned("demo", "1.0.0");
        other_rustc.rustc_version = WireRustcVersion::parse("1.90.0").unwrap();
        let error = validate_plan(
            &task(),
            &task(),
            &[other_rustc],
            &closure(&[("demo", "1.0.0")]),
            &[],
            &[],
            &crate::dep_scan::ProgramClaims::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("rustc 1.90.0"), "{error}");
    }

    #[test]
    fn rejects_reference_that_identity_does_not_produce() {
        let mut artifact = planned("demo", "1.0.0");
        artifact.oci_reference =
            "ghcr.io/water-rs/stow-cache-v2-1.91.1:serde.1.0.210-x-y-z-w".to_owned();
        let error = validate_plan(
            &task(),
            &task(),
            &[artifact],
            &closure(&[("demo", "1.0.0")]),
            &[],
            &[],
            &crate::dep_scan::ProgramClaims::default(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("does not match the reference"),
            "{error}"
        );
    }

    #[test]
    fn rejects_two_artifacts_for_one_reference() {
        let mut second = planned("demo", "1.0.0");
        second.compile_key = "1".repeat(64);
        let plan = vec![planned("demo", "1.0.0"), second];
        let error = validate_plan(
            &task(),
            &task(),
            &plan,
            &closure(&[("demo", "1.0.0")]),
            &[],
            &[],
            &crate::dep_scan::ProgramClaims::default(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("plan contains two artifacts for"),
            "{error}"
        );
    }

    #[test]
    fn rejects_plan_missing_a_closure_library_package() {
        // Containment passes — `demo` is in the closure — but `helper` is a
        // lib package the pipeline compiled and its artifact is missing.
        let plan = vec![planned("demo", "1.0.0")];
        let error = validate_plan(
            &task(),
            &task(),
            &plan,
            &closure_with_libs(
                &[("demo", "1.0.0"), ("helper", "2.0.0")],
                &[("demo", "1.0.0"), ("helper", "2.0.0")],
            ),
            &[],
            &[],
            &crate::dep_scan::ProgramClaims::default(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no build-phase artifact for helper 2.0.0"),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_check_phase_only_artifact_for_a_library_package() {
        // A `dep-info,metadata` entry is the check-phase unit — it carries no
        // rlib, so it cannot stand in for the build-phase artifact.
        let mut check_only = planned("demo", "1.0.0");
        check_only.emit = vec!["dep-info".to_owned(), "metadata".to_owned()];
        check_only.oci_reference = oci_reference(
            &planned_artifact_key(&check_only).unwrap(),
            check_only.c_metadata.as_str(),
        );
        let error = validate_plan(
            &task(),
            &task(),
            &[check_only],
            &closure_with_libs(&[("demo", "1.0.0")], &[("demo", "1.0.0")]),
            &[],
            &[],
            &crate::dep_scan::ProgramClaims::default(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no build-phase artifact for demo 1.0.0"),
            "{error}"
        );
    }

    #[test]
    fn accepts_a_plan_when_only_non_library_packages_are_uncovered() {
        // `binpkg` is in the closure but has no lib target, so the pipeline
        // never produces an artifact for it — its absence must not fail.
        let plan = vec![planned("demo", "1.0.0")];
        validate_plan(
            &task(),
            &task(),
            &plan,
            &closure_with_libs(
                &[("demo", "1.0.0"), ("binpkg", "3.0.0")],
                &[("demo", "1.0.0")],
            ),
            &[],
            &[],
            &crate::dep_scan::ProgramClaims::default(),
        )
        .unwrap();
    }

    #[test]
    fn rejects_task_mismatch() {
        let mut built_for = task();
        built_for.version = CrateVersion::new(semver::Version::new(2, 0, 0));
        let error = validate_plan(
            &task(),
            &built_for,
            &[],
            &closure(&[("demo", "1.0.0")]),
            &[],
            &[],
            &crate::dep_scan::ProgramClaims::default(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("was produced for task"),
            "{error}"
        );
    }
}
