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
    let name = &key.crate_id.name;
    let version = sanitize_oci_tag_component(&key.crate_id.version.to_string());
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

fn sanitize_oci_tag_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect()
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

    #[test]
    fn oci_tag_sanitizes_build_metadata() {
        let key = ArtifactKey {
            crate_id: CrateId {
                name: "libgit2-sys".into(),
                version: semver::Version::parse("0.17.0+1.8.1").expect("valid semver"),
            },
            features: FeatureSet::new(),
            crate_types: vec![RustCrateType::Lib],
            target: Target("aarch64-apple-darwin".into()),
            rustc_version: RustcVersion {
                version: semver::Version::new(1, 91, 1),
                commit_hash: "ed61e7d7e".into(),
                llvm_version: "21.0.0".into(),
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

        let reference = oci_reference(&key, "d44626168446442d");
        let tag = reference.rsplit_once(':').expect("tag separator").1;
        assert!(tag.contains("0.17.0_1.8.1"));
        assert!(!tag.contains('+'));
    }
}
