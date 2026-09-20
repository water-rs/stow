//! Deterministic BLAKE3 hashing of [`ArtifactKey`] for analytics and display.
//!
//! Not the cache lookup path — cache lookup uses the composite key
//! `(c_metadata, target, rustc_version)`.

use crate::artifact::ArtifactKey;

/// Hash version prefix to allow future changes to the hashing algorithm
/// without colliding with previous versions.
const STOW_HASH_VERSION: &[u8] = b"stow-v1";

/// Compute a deterministic BLAKE3 hash of an `ArtifactKey`.
///
/// This hash is used for **analytics and display only**, NOT for cache lookup.
/// Cache lookup uses the composite key `(c_metadata, target, rustc_version)`.
///
/// The hash MUST produce identical output on all platforms. Each field is
/// length-prefixed to prevent ambiguity between adjacent fields.
///
/// # Panics
/// Panics if a field count or hashed string length exceeds `u32::MAX`.
#[must_use]
pub fn compute_artifact_hash(key: &ArtifactKey) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(STOW_HASH_VERSION);

    // Crate identity
    hash_str(&mut hasher, &key.crate_id.name);
    hash_str(&mut hasher, &key.crate_id.version.to_string());

    // Features: sorted iteration guaranteed by BTreeSet
    let feature_count =
        u32::try_from(key.features.0.len()).expect("feature count exceeds u32 range");
    hasher.update(&feature_count.to_le_bytes());
    for f in &key.features.0 {
        hash_str(&mut hasher, f);
    }

    // Target
    hash_str(&mut hasher, &key.target.0);

    // Rustc version
    hash_str(&mut hasher, &key.rustc_version.version.to_string());
    hash_str(&mut hasher, &key.rustc_version.commit_hash);

    // Profile fields in fixed order
    hash_str(&mut hasher, &key.profile.opt_level);
    hasher.update(&key.profile.debuginfo.to_le_bytes());
    hasher.update(&[u8::from(key.profile.debug_assertions)]);
    hasher.update(&[u8::from(key.profile.overflow_checks)]);
    hash_str(&mut hasher, key.profile.panic.as_str());

    let crate_type_count =
        u32::try_from(key.crate_types.len()).expect("crate type count exceeds u32 range");
    hasher.update(&crate_type_count.to_le_bytes());
    for crate_type in &key.crate_types {
        hash_str(&mut hasher, crate_type.as_str());
    }

    // Artifact kind: prevents collision if crate is both lib and proc-macro
    hash_str(&mut hasher, key.kind.as_str());

    hex::encode(hasher.finalize().as_bytes())
}

/// Hash a string with length prefix to prevent ambiguity.
fn hash_str(h: &mut blake3::Hasher, s: &str) {
    let len = u32::try_from(s.len()).expect("hash input string length exceeds u32 range");
    h.update(&len.to_le_bytes());
    h.update(s.as_bytes());
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::artifact::{ArtifactKey, ArtifactKind, RustCrateType};
    use crate::crate_info::{CrateId, FeatureSet};
    use crate::platform::{PanicStrategy, Profile, RustcVersion, Target};

    fn make_key() -> ArtifactKey {
        ArtifactKey {
            crate_id: CrateId {
                name: "serde".into(),
                version: semver::Version::new(1, 0, 210),
            },
            features: FeatureSet(BTreeSet::from(["derive".into(), "default".into()])),
            crate_types: vec![RustCrateType::Rlib],
            target: Target("x86_64-unknown-linux-gnu".into()),
            rustc_version: RustcVersion {
                version: semver::Version::new(1, 83, 0),
                commit_hash: "90b35a623".into(),
                llvm_version: "19.1.4".into(),
            },
            profile: Profile {
                opt_level: "0".into(),
                debuginfo: 2,
                debug_assertions: true,
                overflow_checks: true,
                panic: PanicStrategy::Unwind,
                strip: crate::platform::StripLevel::None,
            },
            kind: ArtifactKind::Rlib,
        }
    }

    #[test]
    fn hash_is_deterministic() {
        let key = make_key();
        let h1 = compute_artifact_hash(&key);
        let h2 = compute_artifact_hash(&key);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_is_64_hex_chars() {
        let key = make_key();
        let h = compute_artifact_hash(&key);
        assert_eq!(h.len(), 64); // BLAKE3 produces 32 bytes = 64 hex chars
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_features_produce_different_hash() {
        let key1 = make_key();
        let mut key2 = make_key();
        key2.features = FeatureSet(BTreeSet::from(["std".into()]));
        assert_ne!(compute_artifact_hash(&key1), compute_artifact_hash(&key2));
    }

    #[test]
    fn different_kind_produces_different_hash() {
        let key1 = make_key();
        let mut key2 = make_key();
        key2.kind = ArtifactKind::ProcMacro;
        assert_ne!(compute_artifact_hash(&key1), compute_artifact_hash(&key2));
    }

    #[test]
    fn different_crate_types_produce_different_hash() {
        let key1 = make_key();
        let mut key2 = make_key();
        key2.crate_types = vec![RustCrateType::Dylib];
        key2.kind = ArtifactKind::Dylib;
        assert_ne!(compute_artifact_hash(&key1), compute_artifact_hash(&key2));
    }

    #[test]
    fn different_target_produces_different_hash() {
        let key1 = make_key();
        let mut key2 = make_key();
        key2.target = Target("aarch64-apple-darwin".into());
        assert_ne!(compute_artifact_hash(&key1), compute_artifact_hash(&key2));
    }

    #[test]
    fn different_rustc_version_produces_different_hash() {
        let key1 = make_key();
        let mut key2 = make_key();
        key2.rustc_version.version = semver::Version::new(1, 84, 0);
        assert_ne!(compute_artifact_hash(&key1), compute_artifact_hash(&key2));
    }

    #[test]
    fn different_profile_produces_different_hash() {
        let key1 = make_key();
        let mut key2 = make_key();
        key2.profile.opt_level = "3".into();
        assert_ne!(compute_artifact_hash(&key1), compute_artifact_hash(&key2));
    }
}
