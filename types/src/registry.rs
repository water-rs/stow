use crate::artifact::ArtifactKey;

/// Base path for OCI artifacts in GHCR.
const GHCR_BASE: &str = "ghcr.io/stow-rs/cache";

/// Compute the OCI reference for an artifact.
///
/// Format: `ghcr.io/stow-rs/cache/{name}:{version}-{target_short}-{rustc_short}-{feat_hash}-{c_metadata}`
///
/// OCI tags have a 128-char limit. We use short forms for target and rustc,
/// and a short hash of the feature set to keep within limits.
pub fn oci_reference(key: &ArtifactKey, c_metadata: &str) -> String {
    let name = repository_segment(&key.crate_id.name);
    let version = tag_version(&key.crate_id.version);
    let target_short = key.target.short();
    let rustc_short = key.rustc_version.short();
    let feat_hash = key.features.short_hash();
    let kind_suffix = match key.kind {
        crate::artifact::ArtifactKind::Rlib => "",
        crate::artifact::ArtifactKind::Dylib => "-dy",
        crate::artifact::ArtifactKind::ProcMacro => "-pm",
    };

    format!(
        "{GHCR_BASE}/{name}:{version}-{target_short}-{rustc_short}-{feat_hash}-{c_metadata}{kind_suffix}"
    )
}

/// Encode a crate version so it is usable as an OCI tag.
///
/// OCI tags accept `[a-zA-Z0-9_][a-zA-Z0-9._-]*`, which excludes the `+` that
/// separates semver build metadata (`jemalloc-sys 0.5.4+5.3.0-patched`). No
/// valid semver identifier contains `_`, so substituting it keeps the mapping
/// injective: two distinct versions never collapse onto the same tag.
fn tag_version(version: &semver::Version) -> String {
    version.to_string().replace('+', "_")
}

/// Encode a crate name so it is usable as an OCI repository path segment.
///
/// Repository segments must be lowercase. crates.io already rejects names that
/// differ from an existing one only by case (or by `-` versus `_`), so folding
/// case cannot make two published crates share a repository.
fn repository_segment(name: &str) -> String {
    name.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::artifact::{ArtifactKey, ArtifactKind, RustCrateType};
    use crate::crate_info::{CrateId, FeatureSet};
    use crate::platform::{PanicStrategy, Profile, RustcVersion, Target};

    #[test]
    fn oci_reference_format() {
        let key = ArtifactKey {
            crate_id: CrateId {
                name: "serde".into(),
                version: semver::Version::new(1, 0, 210),
            },
            features: FeatureSet(BTreeSet::from(["derive".into()])),
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
            },
            kind: ArtifactKind::Rlib,
        };

        let reference = oci_reference(&key, "abcdef0123456789");
        assert!(reference.starts_with("ghcr.io/stow-rs/cache/serde:"));
        assert!(reference.contains("1.0.210"));
        assert!(reference.contains("x86_64-linux"));
        assert!(reference.contains("1.83.0"));
        assert!(reference.contains("abcdef0123456789"));
        // Should not end with -pm for Rlib
        assert!(!reference.ends_with("-pm"));
    }

    #[test]
    fn proc_macro_has_pm_suffix() {
        let key = ArtifactKey {
            crate_id: CrateId {
                name: "serde_derive".into(),
                version: semver::Version::new(1, 0, 210),
            },
            features: FeatureSet::new(),
            crate_types: vec![RustCrateType::ProcMacro],
            target: Target("x86_64-unknown-linux-gnu".into()),
            rustc_version: RustcVersion {
                version: semver::Version::new(1, 83, 0),
                commit_hash: "90b35a623".into(),
                llvm_version: "19.1.4".into(),
            },
            profile: Profile {
                opt_level: "3".into(),
                debuginfo: 0,
                debug_assertions: false,
                overflow_checks: false,
                panic: PanicStrategy::Unwind,
            },
            kind: ArtifactKind::ProcMacro,
        };

        let reference = oci_reference(&key, "abcdef0123456789");
        assert!(reference.ends_with("-pm"));
    }

    fn key_for(name: &str, version: semver::Version) -> ArtifactKey {
        ArtifactKey {
            crate_id: CrateId {
                name: name.into(),
                version,
            },
            features: FeatureSet::new(),
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
            },
            kind: ArtifactKind::Rlib,
        }
    }

    fn tag_of(reference: &str) -> &str {
        reference.rsplit_once(':').expect("reference has a tag").1
    }

    #[test]
    fn build_metadata_versions_produce_a_valid_tag() {
        // `+` is legal in semver but not in an OCI tag, and crates such as
        // jemalloc-sys and toml_edit publish versions that carry it.
        let version = "0.5.4+5.3.0-patched".parse().expect("parse version");
        let reference = oci_reference(&key_for("jemalloc-sys", version), "511e3c88c710b5d5");
        let tag = tag_of(&reference);
        assert!(
            tag.starts_with("0.5.4_5.3.0-patched-"),
            "unexpected tag: {tag}"
        );
        assert!(
            tag.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')),
            "tag has characters OCI rejects: {tag}"
        );
    }

    #[test]
    fn versions_differing_only_in_build_metadata_keep_distinct_tags() {
        let plain = oci_reference(&key_for("demo", "1.2.3".parse().unwrap()), "aaaaaaaaaaaaaaaa");
        let built = oci_reference(
            &key_for("demo", "1.2.3+extra".parse().unwrap()),
            "aaaaaaaaaaaaaaaa",
        );
        assert_ne!(tag_of(&plain), tag_of(&built));
    }

    #[test]
    fn uppercase_crate_names_fold_to_a_lowercase_repository() {
        let reference = oci_reference(
            &key_for("Inflector", "0.11.4".parse().unwrap()),
            "abcdef0123456789",
        );
        assert!(
            reference.starts_with("ghcr.io/stow-rs/cache/inflector:"),
            "unexpected reference: {reference}"
        );
    }

    #[test]
    fn oci_tag_within_128_chars() {
        let key = ArtifactKey {
            crate_id: CrateId {
                name: "some-really-long-crate-name-that-exists".into(),
                version: semver::Version::new(99, 99, 99),
            },
            features: FeatureSet(BTreeSet::from([
                "feature1".into(),
                "feature2".into(),
                "feature3".into(),
            ])),
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
            },
            kind: ArtifactKind::Rlib,
        };

        let reference = oci_reference(&key, "abcdef0123456789");
        // The tag is the part after the last ':'
        let tag = reference.rsplit_once(':').unwrap().1;
        assert!(
            tag.len() <= 128,
            "OCI tag too long: {} chars ({})",
            tag.len(),
            tag
        );
    }
}
