//! Dev rows keep their persisted and signed bytes (stow#1008).
//!
//! The dev profile is the implicit value of the profile field, as it is of
//! the task id: a dev record, index row or scheduler log row serializes
//! exactly as it did before the field existed. The literals were produced
//! by that code.

use stow_types::api::{
    ArtifactRecord, PublishedSliceRow, SchedulerEvent, SubmissionNode, SubmissionSource,
};
use stow_types::artifact::{ArtifactKind, RustCrateType};
use stow_types::identity::{
    CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, DependencyIdentity, FeaturesJson,
    TargetTriple, WireRustcVersion,
};
use stow_types::node_profile::NodeProfile;
use stow_types::platform::{PanicStrategy, Profile, StripLevel};
use stow_types::public_cache::{ExplicitSpelling, UnitInvocation, UnitKind, UnitShape, UnitSide};

const DEV: NodeProfile = NodeProfile::Dev;

const fn shape() -> UnitShape {
    UnitShape {
        side: UnitSide::Target,
        invocation: UnitInvocation::Native,
        kind: UnitKind::Linked,
    }
}

fn record(node_profile: NodeProfile) -> ArtifactRecord {
    ArtifactRecord {
        compile_key: "key".to_owned(),
        c_metadata: CMetadata::parse("0123456789abcdef").unwrap(),
        extra_filename: "-0123456789abcdef".to_owned(),
        target: TargetTriple::parse("x86_64-unknown-linux-gnu").unwrap(),
        rustc_version: WireRustcVersion::parse("1.91.1").unwrap(),
        profile: Profile {
            opt_level: "0".to_owned(),
            debuginfo: 2,
            debug_assertions: true,
            overflow_checks: true,
            panic: PanicStrategy::Unwind,
            strip: StripLevel::None,
        },
        node_profile,
        emit: vec!["link".to_owned()],
        crate_name: CrateName::parse("itoa").unwrap(),
        version: CrateVersion::new(semver::Version::new(1, 0, 15)),
        features_json: FeaturesJson::default(),
        dependency_c_metadata_json: DependencyCMetadataJson::default(),
        dependency_task_ids: vec!["dep-1".to_owned()],
        oci_reference: "ghcr.io/water-rs/stow-cache:itoa".to_owned(),
        oci_digest: "sha256:aa".to_owned(),
        has_native: false,
        artifact_kind: ArtifactKind::Rlib,
        crate_types: vec![RustCrateType::Rlib],
        artifact_size: 10,
        bundle_digest: "sha256:bb".to_owned(),
        bundle_size: 100,
        compile_millis: 5,
        unit_shape: shape(),
        min_glibc: None,
    }
}

fn submission(profile: NodeProfile) -> SubmissionNode {
    SubmissionNode {
        task_id: "itoa-task".to_owned(),
        crate_name: CrateName::parse("itoa").unwrap(),
        version: CrateVersion::new(semver::Version::new(1, 0, 15)),
        features_json: FeaturesJson::default(),
        target: TargetTriple::parse("x86_64-unknown-linux-gnu").unwrap(),
        rustc_version: WireRustcVersion::parse("1.91.1").unwrap(),
        host_side: false,
        profile,
        explicit_spelling: ExplicitSpelling::KeysAsNative,
        preserve_lockfile: false,
        dependency_identity: DependencyIdentity::from_task_ids(["dep-1"]).unwrap(),
        deps: Vec::new(),
        downloads: 3,
    }
}

fn slice_row(node_profile: NodeProfile) -> PublishedSliceRow {
    PublishedSliceRow {
        crate_name: CrateName::parse("itoa").unwrap(),
        version: CrateVersion::new(semver::Version::new(1, 0, 15)),
        features_json: FeaturesJson::default(),
        node_profile,
        unit_shape: shape(),
        dependency_identity: DependencyIdentity::from_task_ids(["dep-1"]).unwrap(),
    }
}

fn submit(profile: NodeProfile) -> SchedulerEvent {
    SchedulerEvent::Submit {
        source: SubmissionSource::CacheMiss,
        part: 0,
        parts: 1,
        roots: vec![0],
        nodes: vec![submission(profile)],
    }
}

fn report(node_profile: NodeProfile) -> SchedulerEvent {
    SchedulerEvent::SliceReport {
        target: TargetTriple::parse("x86_64-unknown-linux-gnu").unwrap(),
        rustc_version: WireRustcVersion::parse("1.91.1").unwrap(),
        base_generation: None,
        generation: 1,
        part: 0,
        parts: 1,
        added: vec![slice_row(node_profile)],
        retired: Vec::new(),
    }
}

fn json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap()
}

#[test]
fn a_dev_record_serializes_as_it_did_before_profiles() {
    let record = record(DEV);
    assert_eq!(json(&record), GOLDEN_RECORD);
    let row = stow_types::records::record_to_index_row(&record);
    assert_eq!(json(&row), GOLDEN_INDEX_ROW);
}

#[test]
fn a_dev_log_row_serializes_as_it_did_before_profiles() {
    assert_eq!(json(&submit(DEV)), GOLDEN_SUBMIT);
    assert_eq!(json(&report(DEV)), GOLDEN_REPORT);
}

/// An absent field is dev, and another profile is written and read back.
#[test]
fn only_another_profile_is_written() {
    let release = NodeProfile::Release;
    for (dev, other) in [
        (json(&record(DEV)), json(&record(release))),
        (json(&submit(DEV)), json(&submit(release))),
        (json(&report(DEV)), json(&report(release))),
    ] {
        assert!(
            !dev.contains("profile\":\"") && !dev.contains("_profile"),
            "{dev}"
        );
        assert!(other.contains("\"release\""), "{other}");
    }
    let back: ArtifactRecord = serde_json::from_str(&json(&record(release))).unwrap();
    assert_eq!(back.node_profile, release);
    let back: ArtifactRecord = serde_json::from_str(GOLDEN_RECORD).unwrap();
    assert_eq!(back.node_profile, DEV);
}

const GOLDEN_RECORD: &str = r#"{"compile_key":"key","c_metadata":"0123456789abcdef","extra_filename":"-0123456789abcdef","target":"x86_64-unknown-linux-gnu","rustc_version":"1.91.1","profile":{"opt_level":"0","debuginfo":2,"debug_assertions":true,"overflow_checks":true,"panic":"Unwind"},"emit":["link"],"crate_name":"itoa","version":"1.0.15","features_json":"[]","dependency_c_metadata_json":"[]","dependency_task_ids":["dep-1"],"oci_reference":"ghcr.io/water-rs/stow-cache:itoa","oci_digest":"sha256:aa","has_native":false,"artifact_kind":"Rlib","crate_types":["rlib"],"artifact_size":10,"bundle_digest":"sha256:bb","bundle_size":100,"compile_millis":5,"unit_shape":{"side":"target","invocation":"native","kind":"linked"}}"#;
const GOLDEN_INDEX_ROW: &str = r#"{"crate_name":"itoa","version":"1.0.15","features_json":"[]","dependency_c_metadata_json":"[]","dependency_task_ids":["dep-1"],"c_metadata":"0123456789abcdef","compile_key":"key","bundle_digest":"sha256:bb","bundle_size":100,"artifact_kind":"Rlib","crate_types":["rlib"],"profile":{"opt_level":"0","debuginfo":2,"debug_assertions":true,"overflow_checks":true,"panic":"Unwind"},"emit":["link"],"unit_shape":{"side":"target","invocation":"native","kind":"linked"}}"#;
const GOLDEN_SUBMIT: &str = r#"{"event":"submit","source":{"kind":"cache_miss"},"part":0,"parts":1,"roots":[0],"nodes":[{"task_id":"itoa-task","crate_name":"itoa","version":"1.0.15","features_json":"[]","target":"x86_64-unknown-linux-gnu","rustc_version":"1.91.1","host_side":false,"explicit_spelling":"keys-as-native","preserve_lockfile":false,"dependency_identity":"f2cd7d1afd08acbed942ef42d4eb3d16df62ee01f24c93de0ad4cab2c01cf8a9","downloads":3}]}"#;
const GOLDEN_REPORT: &str = r#"{"event":"slice_report","target":"x86_64-unknown-linux-gnu","rustc_version":"1.91.1","generation":1,"part":0,"parts":1,"added":[{"crate_name":"itoa","version":"1.0.15","features_json":"[]","unit_shape":{"side":"target","invocation":"native","kind":"linked"},"dependency_identity":"f2cd7d1afd08acbed942ef42d4eb3d16df62ee01f24c93de0ad4cab2c01cf8a9"}],"retired":[]}"#;
