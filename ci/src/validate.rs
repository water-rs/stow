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
) -> stow_types::error::Result<()> {
    if built_task != task {
        return Err(stow_types::stow_error!(
            "build output was produced for task {} but the publisher was dispatched for task {}",
            built_task.task_id,
            task.task_id
        ));
    }

    validate_consumed_claims(task, closure, consumed, index_slices)?;

    let mut references = BTreeMap::<&str, &PlannedArtifact>::new();
    for artifact in plan {
        if artifact.target != task.target {
            return Err(stow_types::stow_error!(
                "planned artifact {} targets {} but the task targets {}",
                artifact.oci_reference,
                artifact.target,
                task.target
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
                && artifact.emit.iter().any(|emit| emit == "link")
        }) || consumed.iter().any(|claim| {
            claim.crate_name.as_str() == name.as_str()
                && claim.crate_version == version.to_string()
                && claim.emit.iter().any(|emit| emit == "link")
        });
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
        if canonical_crate_name(claim.crate_name.as_str())
            == canonical_crate_name(task.crate_name.as_str())
            && claim.crate_version == task.version.to_string()
        {
            return Err(stow_types::stow_error!(
                "consumed artifact claims the task crate {} {} itself — each build must compile its own crate",
                claim.crate_name,
                claim.crate_version
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
        let vouched = index_slices
            .iter()
            .filter(|slice| slice.index.header.target.as_str() == claim.target)
            .flat_map(|slice| slice.index.rows.iter())
            .any(|row| {
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
            });
        if !vouched {
            return Err(stow_types::stow_error!(
                "consumed artifact {} {} (compile_key {}, c_metadata {}, target {}) matches no row of the signed index — a cache hit the index does not vouch for is a dropped compile",
                claim.crate_name,
                claim.crate_version,
                claim.compile_key,
                claim.c_metadata,
                claim.target
            ));
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
        DependencyClosure::from_packages(to_set(packages), to_set(lib_packages))
    }

    fn planned(crate_name: &str, version: &str) -> PlannedArtifact {
        let mut artifact = PlannedArtifact {
            compile_key: "0".repeat(64),
            crate_name: CrateName::parse(crate_name).unwrap(),
            crate_version: CrateVersion::new(semver::Version::parse(version).unwrap()),
            c_metadata: CMetadata::parse("0123456789abcdef").unwrap(),
            extra_filename: "-0123456789abcdef".to_owned(),
            features_json: FeaturesJson::default(),
            dependency_c_metadata_json: DependencyCMetadataJson::default(),
            dependency_compile_keys_json: "[]".to_owned(),
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
        )
        .unwrap();
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
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("not in the resolved closure"),
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
        )
        .unwrap_err();
        assert!(error.to_string().contains("rustc 1.90.0"), "{error}");
    }

    #[test]
    fn rejects_reference_that_identity_does_not_produce() {
        let mut artifact = planned("demo", "1.0.0");
        artifact.oci_reference = "ghcr.io/water-rs/stow-cache:serde.1.0.210-x-y-z-w".to_owned();
        let error = validate_plan(
            &task(),
            &task(),
            &[artifact],
            &closure(&[("demo", "1.0.0")]),
            &[],
            &[],
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
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("was produced for task"),
            "{error}"
        );
    }
}
