//! CF-cache keys for artifact-row lookups and bundle payloads, kept
//! target-agnostic so the derivations are unit-testable outside wasm.

/// Bundle-bytes schema version baked into the CF-cache bundle keys. Bump
/// only when the bundle format itself changes; a key-shape change mints
/// fresh keys that simply miss and refill. Version 3 is the first whose
/// bytes are the publish stage's `<tag>.bundle` blob rather than an
/// edge-assembled tar.
pub const EDGE_BUNDLE_SCHEMA_VERSION: u32 = 3;

/// Row-shape version baked into the lookup-cache keys. Bump when the
/// cached `ArtifactRow` gains a field a serving handler depends on, so
/// entries written by the previous deploy miss instead of parsing without
/// it. Version 2 added the bundle coordinates.
pub const LOOKUP_ROW_VERSION: u32 = 2;

/// Lookup-cache key for the exact `(target, rustc_version, c_metadata)`
/// identity — everything needed to re-resolve the D1 row.
pub fn exact_lookup_key(target: &str, rustc_version: &str, c_metadata: &str) -> String {
    format!("v{LOOKUP_ROW_VERSION}/exact/{target}/{rustc_version}/{c_metadata}")
}

/// CF-cache key for a bundle. The bundle is the content-addressed blob the
/// trusted publish stage pushed, so `bundle_digest` pins the bytes; every
/// exact lookup that resolves to the same row shares one cached object.
pub fn bundle_cache_key(target: &str, rustc_version: &str, bundle_digest: &str) -> String {
    format!("bundle-v{EDGE_BUNDLE_SCHEMA_VERSION}/{target}/{rustc_version}/{bundle_digest}")
}

#[cfg(test)]
mod tests {
    use stow_types::api::ArtifactRecord;
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::identity::{
        CMetadata, CrateName, CrateVersion, DependencyCMetadataIdentity, DependencyCMetadataJson,
        FeaturesJson, WireRustcVersion,
    };
    use stow_types::platform::{PanicStrategy, Profile};

    use super::*;

    fn test_profile() -> Profile {
        Profile {
            opt_level: "0".to_owned(),
            debuginfo: 0,
            debug_assertions: true,
            overflow_checks: true,
            panic: PanicStrategy::Unwind,
            strip: stow_types::platform::StripLevel::None,
        }
    }

    fn test_record() -> ArtifactRecord {
        ArtifactRecord {
            compile_key: "aaaaaaaaaaaaaaaaffffffffffffffff".to_owned(),
            c_metadata: CMetadata::parse("aaaaaaaaaaaaaaaa").expect("c_metadata"),
            extra_filename: "-aaaaaaaaaaaaaaaa".to_owned(),
            target: "x86_64-unknown-linux-gnu".parse().expect("target"),
            rustc_version: WireRustcVersion::parse("1.98.1").expect("rustc"),
            profile: test_profile(),
            emit: vec!["link".to_owned()],
            crate_name: CrateName::parse("serde").expect("name"),
            version: CrateVersion::new(semver::Version::parse("1.0.0").expect("version")),
            features_json: FeaturesJson::canonicalize(vec!["default".to_owned()]).expect("features"),
            dependency_c_metadata_json: DependencyCMetadataJson::canonicalize(vec![
                DependencyCMetadataIdentity {
                    crate_name: CrateName::parse("dep").expect("dep name"),
                    c_metadata: CMetadata::parse("dddddddddddddddd").expect("dep c_metadata"),
                },
            ])
            .expect("deps"),
            oci_reference: "ghcr.io/water-rs/stow-cache:serde.1.0.0-x86_64-linux-1.98.1-abcdef012345-aaaaaaaaaaaaaaaa".to_owned(),
            oci_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
            has_native: false,
            artifact_kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Rlib],
            artifact_size: 1024,
            bundle_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            bundle_size: 1,
            compile_millis: 60,
        }
    }

    /// The bundle key is content-addressed: the publish stage's bundle
    /// digest pins the bytes, so neither `created_at` (issue #170) nor the
    /// lookup surface joins the key.
    #[test]
    fn bundle_cache_key_pins_the_bundle_digest() {
        assert_eq!(
            bundle_cache_key("x86_64-unknown-linux-gnu", "1.98.1", "sha256:bbbb"),
            format!(
                "bundle-v{EDGE_BUNDLE_SCHEMA_VERSION}/x86_64-unknown-linux-gnu/1.98.1/sha256:bbbb"
            ),
        );
    }

    #[test]
    fn artifact_row_json_round_trips_for_lookup_cache() {
        let record = test_record();
        let row = crate::db::ArtifactRow {
            c_metadata: record.c_metadata.as_str().to_owned(),
            oci_reference: record.oci_reference.clone(),
            oci_digest: record.oci_digest.clone(),
            created_at: "2026-05-09 00:00:00".to_owned(),
            artifact_size: Some(record.artifact_size),
            bundle_digest: record.bundle_digest.clone(),
            bundle_size: record.bundle_size,
            crate_name: record.crate_name.as_str().to_owned(),
            version: record.version.to_string(),
            compile_millis: record.compile_millis,
        };
        let bytes = serde_json::to_vec(&row).expect("serialize");
        let decoded: crate::db::ArtifactRow = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(decoded.oci_digest, row.oci_digest);
        assert_eq!(decoded.bundle_digest, row.bundle_digest);
        assert_eq!(decoded.bundle_size, row.bundle_size);
        assert_eq!(decoded.artifact_size, row.artifact_size);
        assert_eq!(decoded.c_metadata, row.c_metadata);
        assert_eq!(decoded.crate_name, row.crate_name);
        assert_eq!(decoded.version, row.version);
        assert_eq!(decoded.compile_millis, row.compile_millis);
    }
}
