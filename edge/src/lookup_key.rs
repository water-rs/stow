//! CF-cache keys for artifact-row lookups and bundle payloads, kept
//! target-agnostic so the derivations are unit-testable outside wasm.

use stow_types::api::{ArtifactRecord, SemanticArtifactRequest};
use stow_types::artifact::RustCrateType;
use stow_types::identity::CrateVersion;
use stow_types::platform::Profile;

/// Bundle-bytes schema version baked into the CF-cache bundle keys. Bump
/// only when the assembled bundle format itself changes; a key-shape
/// change mints fresh keys that simply miss and refill.
pub const EDGE_BUNDLE_SCHEMA_VERSION: u32 = 2;

/// Lookup-cache key for the exact `(target, rustc_version, c_metadata)`
/// identity — everything needed to re-resolve the D1 row.
pub fn exact_lookup_key(target: &str, rustc_version: &str, c_metadata: &str) -> String {
    format!("v1/exact/{target}/{rustc_version}/{c_metadata}")
}

/// CF-cache key for the edge-assembled bundle of an exact artifact row.
/// `oci_digest` already content-pins the bytes; the row's `created_at`
/// must not join this key — it is preserved across re-registers, and
/// keying on it orphaned the cached bundle on every idempotent
/// re-register.
pub fn exact_cache_key(
    target: &str,
    rustc_version: &str,
    c_metadata: &str,
    oci_digest: &str,
) -> String {
    format!(
        "bundle-v{EDGE_BUNDLE_SCHEMA_VERSION}/{target}/{rustc_version}/{c_metadata}/{oci_digest}"
    )
}

/// CF-cache key for the bundle a semantic request resolves to. As with
/// [`exact_cache_key`], `oci_digest` is the only row field in the key —
/// the resolved row's `created_at` is deliberately absent.
pub fn semantic_cache_key(request: &SemanticArtifactRequest, oci_digest: &str) -> String {
    let profile_json =
        serde_json::to_string(&request.profile).expect("semantic profile serialization must work");
    let emit_json =
        serde_json::to_string(&request.emit).expect("semantic emit serialization must work");
    let crate_types_json = serde_json::to_string(&request.crate_types)
        .expect("semantic crate_types serialization must work");
    format!(
        "semantic/bundle-v{EDGE_BUNDLE_SCHEMA_VERSION}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}",
        request.target,
        request.rustc_version,
        request.crate_name,
        request.version,
        request.features_json,
        profile_json,
        emit_json,
        request.kind.as_str(),
        crate_types_json,
        oci_digest,
    )
}

/// The request surface that decides which artifact row a semantic lookup
/// resolves to — including `dependency_c_metadata_json`, which the D1
/// query filters on. `ArtifactRecord` carries the same fields, so
/// registration can rebuild the identical key to invalidate it.
pub struct SemanticLookupSurface<'a> {
    target: &'a str,
    rustc_version: &'a str,
    crate_name: &'a str,
    version: &'a CrateVersion,
    features_json: String,
    dependency_c_metadata_json: String,
    profile: &'a Profile,
    emit: &'a [String],
    kind: &'a str,
    crate_types: &'a [RustCrateType],
}

impl SemanticLookupSurface<'_> {
    pub fn key(&self) -> String {
        let profile_json =
            serde_json::to_string(self.profile).expect("semantic profile serialization must work");
        let emit_json =
            serde_json::to_string(self.emit).expect("semantic emit serialization must work");
        let crate_types_json = serde_json::to_string(self.crate_types)
            .expect("semantic crate_types serialization must work");
        format!(
            "v1/semantic/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}",
            self.target,
            self.rustc_version,
            self.crate_name,
            self.version,
            self.features_json,
            self.dependency_c_metadata_json,
            profile_json,
            emit_json,
            self.kind,
            crate_types_json,
        )
    }
}

impl<'a> From<&'a SemanticArtifactRequest> for SemanticLookupSurface<'a> {
    fn from(request: &'a SemanticArtifactRequest) -> Self {
        Self {
            target: request.target.as_str(),
            rustc_version: request.rustc_version.as_str(),
            crate_name: request.crate_name.as_str(),
            version: &request.version,
            features_json: request.features_json.raw(),
            dependency_c_metadata_json: request.dependency_c_metadata_json.raw(),
            profile: &request.profile,
            emit: &request.emit,
            kind: request.kind.as_str(),
            crate_types: &request.crate_types,
        }
    }
}

impl<'a> From<&'a ArtifactRecord> for SemanticLookupSurface<'a> {
    fn from(record: &'a ArtifactRecord) -> Self {
        Self {
            target: record.target.as_str(),
            rustc_version: record.rustc_version.as_str(),
            crate_name: record.crate_name.as_str(),
            version: &record.version,
            features_json: record.features_json.raw(),
            dependency_c_metadata_json: record.dependency_c_metadata_json.raw(),
            profile: &record.profile,
            emit: &record.emit,
            kind: record.artifact_kind.as_str(),
            crate_types: &record.crate_types,
        }
    }
}

#[cfg(test)]
mod tests {
    use stow_types::artifact::ArtifactKind;
    use stow_types::identity::{
        CMetadata, CrateName, DependencyCMetadataIdentity, DependencyCMetadataJson, FeaturesJson,
        WireRustcVersion,
    };
    use stow_types::platform::PanicStrategy;

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
        }
    }

    fn matching_request(record: &ArtifactRecord) -> SemanticArtifactRequest {
        SemanticArtifactRequest {
            crate_name: record.crate_name.clone(),
            version: record.version.clone(),
            features_json: record.features_json.clone(),
            dependency_c_metadata_json: record.dependency_c_metadata_json.clone(),
            target: record.target.clone(),
            rustc_version: record.rustc_version.clone(),
            profile: record.profile.clone(),
            emit: record.emit.clone(),
            kind: record.artifact_kind.clone(),
            crate_types: record.crate_types.clone(),
        }
    }

    /// Registration invalidation rebuilds the semantic lookup key from the
    /// artifact record — if the two derivations ever disagree, replaced
    /// rows would keep serving stale entries until TTL expiry.
    #[test]
    fn semantic_lookup_key_matches_between_request_and_record() {
        let record = test_record();
        let request = matching_request(&record);
        assert_eq!(
            SemanticLookupSurface::from(&request).key(),
            SemanticLookupSurface::from(&record).key(),
        );
    }

    #[test]
    fn semantic_lookup_key_changes_with_dependency_closure() {
        let mut other = test_record();
        other.dependency_c_metadata_json = DependencyCMetadataJson::default();
        let request = matching_request(&test_record());
        assert_ne!(
            SemanticLookupSurface::from(&request).key(),
            SemanticLookupSurface::from(&other).key(),
        );
    }

    /// Issue #170 regression: `created_at` must not be a bundle-key
    /// segment — an idempotent re-register preserves it, so keying on it
    /// orphaned the cached bundle and forced a cold GHCR refetch.
    #[test]
    fn exact_cache_key_pins_digest_without_created_at() {
        assert_eq!(
            exact_cache_key(
                "x86_64-unknown-linux-gnu",
                "1.98.1",
                "aaaaaaaaaaaaaaaa",
                "sha256:bbbb",
            ),
            format!(
                "bundle-v{EDGE_BUNDLE_SCHEMA_VERSION}/x86_64-unknown-linux-gnu/1.98.1/aaaaaaaaaaaaaaaa/sha256:bbbb"
            ),
        );
    }

    #[test]
    fn semantic_cache_key_ends_at_digest() {
        let request = matching_request(&test_record());
        let key = semantic_cache_key(&request, "sha256:bbbb");
        assert!(key.ends_with("/sha256:bbbb"));
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
        };
        let bytes = serde_json::to_vec(&row).expect("serialize");
        let decoded: crate::db::ArtifactRow = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(decoded.oci_digest, row.oci_digest);
        assert_eq!(decoded.artifact_size, row.artifact_size);
        assert_eq!(decoded.c_metadata, row.c_metadata);
    }
}
