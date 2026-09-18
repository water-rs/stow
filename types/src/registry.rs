//! GHCR OCI reference construction and parsing for stow artifacts.

use crate::artifact::ArtifactKey;

/// The one literal every GHCR path derives from, so the repository can only
/// ever be spelled once. `concat!` needs a literal, hence the macro.
macro_rules! ghcr_repository {
    () => {
        "water-rs/stow-cache"
    };
}

/// The single GHCR repository every stow artifact is a tag of:
/// `ghcr.io/water-rs/stow-cache`.
///
/// GHCR creates every package private and offers no API to change
/// visibility, so the whole cache shares one package whose visibility is
/// flipped once.
pub const GHCR_REPOSITORY: &str = ghcr_repository!();
/// Base path for OCI references: `ghcr.io/water-rs/stow-cache`.
pub const GHCR_BASE: &str = concat!("ghcr.io/", ghcr_repository!());
/// Registry API base the edge fetches blobs and manifests from.
pub const GHCR_V2_BASE_URL: &str = concat!("https://ghcr.io/v2/", ghcr_repository!());

/// The tag of a canonical stow `oci_reference` produced by [`oci_reference`]
/// — everything after `ghcr.io/water-rs/stow-cache:`. The edge builds
/// `/manifests/<tag>` request URLs from it.
///
/// Returns `None` when the reference lacks the canonical prefix or names an
/// empty tag.
#[must_use]
pub fn oci_reference_tag(reference: &str) -> Option<&str> {
    let tag = reference.strip_prefix(GHCR_BASE)?.strip_prefix(':')?;
    (!tag.is_empty()).then_some(tag)
}

/// Extract the crate-name segment from a canonical stow `oci_reference`
/// produced by [`oci_reference`].
///
/// The crate is the tag's first `.`-separated segment: crates.io names are
/// `[A-Za-z0-9_-]` and never contain `.`, so `sha-1.0.10.0-…` splits
/// unambiguously into crate `sha-1` and version `0.10.0`.
///
/// Returns `None` when the reference lacks the canonical
/// `ghcr.io/water-rs/stow-cache:` prefix, when the crate segment is empty,
/// or when nothing follows the first `.`.
#[must_use]
pub fn oci_reference_name(reference: &str) -> Option<&str> {
    let tag = oci_reference_tag(reference)?;
    let (name, rest) = tag.split_once('.')?;
    (!name.is_empty() && !rest.is_empty()).then_some(name)
}

/// The repository path of an OCI reference.
///
/// The segments between the registry host and the tag or digest
/// (`water-rs/stow-cache` in `ghcr.io/water-rs/stow-cache:serde.1.0.0-…`).
/// Registry `pull` scopes name this path (`repository:<path>:pull`), not the
/// crate segment inside the tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RepositoryPath<'a>(&'a str);

impl<'a> RepositoryPath<'a> {
    /// The full `a/b/c` repository path.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

impl std::fmt::Display for RepositoryPath<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

/// Extract the repository path from an OCI reference.
///
/// `ghcr.io/water-rs/stow-cache:serde.1.0.0-…` → `water-rs/stow-cache`.
/// Both `:tag` and `@digest` reference forms are accepted, and a leading
/// `scheme://` is ignored.
///
/// Returns `None` when the reference is not `<host>/<path>` followed by a
/// tag or digest.
#[must_use]
pub fn repository_path(reference: &str) -> Option<RepositoryPath<'_>> {
    let without_scheme = reference
        .split_once("://")
        .map_or(reference, |(_, rest)| rest);
    let path = match without_scheme.split_once('@') {
        Some((head, _digest)) => head,
        None => without_scheme
            .rsplit_once(':')
            .map_or(without_scheme, |(head, _tag)| head),
    };
    let (_host, repository) = path.split_once('/')?;
    (!repository.is_empty()).then_some(RepositoryPath(repository))
}

/// Compute the OCI reference for an artifact.
///
/// Format: `ghcr.io/water-rs/stow-cache:{name}.{version}-{target_short}-{rustc_short}-{feat_hash}-{c_metadata}{kind_suffix}`
///
/// Every artifact is a tag of the single `water-rs/stow-cache` package; the
/// crate name is the tag's first `.`-separated segment, so
/// `sha-1.0.10.0-…` is crate `sha-1`, version `0.10.0`.
///
/// OCI tags have a 128-char limit: crates.io names are at most 64 chars and
/// the remainder (`{version}-{target_short}-{rustc_short}-{feat_hash}-{c_metadata}{kind_suffix}`)
/// is about 50, so the tag fits with room to spare. We use short forms for
/// target and rustc, and a short hash of the feature set, to keep it that
/// way.
#[must_use]
pub fn oci_reference(key: &ArtifactKey, c_metadata: &str) -> String {
    let name = crate_tag_segment(&key.crate_id.name);
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
        "{GHCR_BASE}:{name}.{version}-{target_short}-{rustc_short}-{feat_hash}-{c_metadata}{kind_suffix}"
    )
}

/// The crate segment stays lowercase even though OCI tags are
/// case-sensitive and crate names need not be (`Inflector`, `RustyXML`, …).
/// crates.io already rejects a new name that differs from a published one
/// only by case (or by `-` vs `_`), so folding case cannot make two distinct
/// published crates collide on one tag prefix.
fn crate_tag_segment(name: &str) -> String {
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
        assert!(reference.starts_with("ghcr.io/water-rs/stow-cache:serde."));
        assert!(reference.contains("1.0.210"));
        assert!(reference.contains("x86_64-linux"));
        assert!(reference.contains("1.83.0"));
        assert!(reference.contains("abcdef0123456789"));
        assert_eq!(oci_reference_name(&reference), Some("serde"));
        // Should not end with -pm for Rlib
        assert!(!reference.ends_with("-pm"));
    }

    #[test]
    fn oci_reference_name_splits_at_first_dot() {
        // `sha-1` 0.10.0: crate names never contain `.`, so the first `.`
        // splits `sha-1` from `0.10.0-…` unambiguously.
        let key = ArtifactKey {
            crate_id: CrateId {
                name: "sha-1".into(),
                version: semver::Version::new(0, 10, 0),
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
        assert!(reference.starts_with("ghcr.io/water-rs/stow-cache:sha-1.0.10.0-"));
        assert_eq!(oci_reference_name(&reference), Some("sha-1"));
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
    fn oci_crate_segment_is_lowercased() {
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
            !oci_reference_tag(&reference)
                .expect("canonical reference shape")
                .split('.')
                .next()
                .expect("tag is non-empty")
                .chars()
                .any(char::is_uppercase)
        );
    }

    #[test]
    fn oci_reference_tag_yields_the_tag() {
        assert_eq!(
            oci_reference_tag(
                "ghcr.io/water-rs/stow-cache:serde.1.0.0-x86_64-linux-1.91.1-abcdef012345-0123"
            ),
            Some("serde.1.0.0-x86_64-linux-1.91.1-abcdef012345-0123")
        );
    }

    #[test]
    fn canonical_parsers_reject_non_canonical_references() {
        for reference in [
            // The retired per-crate layout.
            "ghcr.io/water-rs/stow-cache/serde:1.0.0",
            "ghcr.io/water-rs/other:serde.1.0.0",
            "ghcr.io/water-rs/stow-cache:",
            "ghcr.io/water-rs/stow-cache",
            "",
        ] {
            assert_eq!(
                oci_reference_tag(reference),
                None,
                "reference should fail: {reference}"
            );
            assert_eq!(
                oci_reference_name(reference),
                None,
                "reference should fail: {reference}"
            );
        }
        // The tag parses but there is no `{crate}.{rest}` split.
        for reference in [
            "ghcr.io/water-rs/stow-cache:.1.0.0",
            "ghcr.io/water-rs/stow-cache:serde",
            "ghcr.io/water-rs/stow-cache:serde.",
        ] {
            assert_eq!(
                oci_reference_name(reference),
                None,
                "reference should fail: {reference}"
            );
        }
    }

    #[test]
    fn repository_path_from_tag_reference() {
        let path = repository_path(
            "ghcr.io/water-rs/stow-cache:serde.1.0.0-x86_64-linux-1.91.1-abcdef012345-0123",
        )
        .expect("canonical reference");
        assert_eq!(path.as_str(), "water-rs/stow-cache");
        assert_eq!(path.to_string(), "water-rs/stow-cache");
    }

    #[test]
    fn repository_path_from_digest_reference() {
        let path = repository_path("ghcr.io/water-rs/stow-cache@sha256:deadbeef")
            .expect("digest reference");
        assert_eq!(path.as_str(), "water-rs/stow-cache");
    }

    #[test]
    fn repository_path_handles_scheme_and_single_segment_repo() {
        let path =
            repository_path("https://registry.local/serde:tag").expect("single-segment repo");
        assert_eq!(path.as_str(), "serde");
    }

    #[test]
    fn repository_path_rejects_non_reference() {
        for reference in ["ghcr.io", "ghcr.io/", "serde", "serde:tag", ""] {
            assert_eq!(
                repository_path(reference),
                None,
                "reference should fail: {reference}"
            );
        }
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
