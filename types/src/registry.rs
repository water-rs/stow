use crate::artifact::ArtifactKey;

/// The one literal every GHCR path derives from, so the namespace can only
/// ever be spelled once. `concat!` needs a literal, hence the macro.
macro_rules! ghcr_namespace {
    () => {
        "water-rs/stow-cache"
    };
}

/// GHCR namespace (organization plus repository prefix) that holds every
/// stow artifact: `ghcr.io/water-rs/stow-cache/{crate}`.
pub const GHCR_NAMESPACE: &str = ghcr_namespace!();
/// Base path for OCI references: `ghcr.io/water-rs/stow-cache`.
pub const GHCR_BASE: &str = concat!("ghcr.io/", ghcr_namespace!());
/// Registry API base the edge fetches blobs and manifests from.
pub const GHCR_V2_BASE_URL: &str = concat!("https://ghcr.io/v2/", ghcr_namespace!());

/// Extract the OCI repository name (the crate-name segment) from a canonical
/// stow `oci_reference` produced by [`oci_reference`]. Returns `None` when
/// the reference does not have the canonical `ghcr.io/water-rs/stow-cache/{name}:{tag}`
/// shape.
#[must_use]
pub fn oci_reference_name(reference: &str) -> Option<&str> {
    let remainder = reference.strip_prefix(GHCR_BASE)?.strip_prefix('/')?;
    let (name, tag) = remainder.split_once(':')?;
    (!name.is_empty() && !tag.is_empty()).then_some(name)
}

/// Compute the OCI reference for an artifact.
///
/// Format: `ghcr.io/water-rs/stow-cache/{name}:{version}-{target_short}-{rustc_short}-{feat_hash}-{c_metadata}`
///
/// OCI tags have a 128-char limit. We use short forms for target and rustc,
/// and a short hash of the feature set to keep within limits.
#[must_use]
pub fn oci_reference(key: &ArtifactKey, c_metadata: &str) -> String {
    let name = repository_segment(&key.crate_id.name);
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

/// OCI repository path segments must be lowercase, but crate names need not
/// be (`Inflector`, `RustyXML`, …). crates.io already rejects a new name that
/// differs from a published one only by case (or by `-` vs `_`), so folding
/// case cannot make two distinct published crates collide on one repository.
fn repository_segment(name: &str) -> String {
    name.to_ascii_lowercase()
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
        assert!(reference.starts_with("ghcr.io/water-rs/stow-cache/serde:"));
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
    fn oci_repository_segment_is_lowercased() {
        let key = ArtifactKey {
            crate_id: CrateId {
                name: "Inflector".into(),
                version: semver::Version::new(0, 11, 4),
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
        };

        let reference = oci_reference(&key, "abcdef0123456789");
        let name = oci_reference_name(&reference).expect("canonical reference shape");
        assert_eq!(name, "inflector");
        assert!(
            !reference
                .trim_start_matches(GHCR_BASE)
                .chars()
                .take_while(|ch| *ch != ':')
                .any(char::is_uppercase)
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
