//! GHCR OCI reference construction and parsing for stow artifacts.

use sha2::Digest as _;

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

/// Tag suffix of the assembled bundle artifact published next to every
/// signed artifact: `ghcr.io/water-rs/stow-cache:<tag>.bundle` carries the
/// bundle tar as its single layer.
pub const BUNDLE_TAG_SUFFIX: &str = ".bundle";

/// The OCI distribution spec's tag limit, which GHCR enforces:
/// `[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`.
pub const MAX_OCI_TAG_LEN: usize = 128;

/// Whether `tag` is a legal OCI tag.
fn is_oci_tag(tag: &str) -> bool {
    let mut chars = tag.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    tag.len() <= MAX_OCI_TAG_LEN
        && (first.is_ascii_alphanumeric() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

/// The tag of a canonical stow `oci_reference` produced by [`oci_reference`]
/// — everything after `ghcr.io/water-rs/stow-cache:`. The edge builds
/// `/manifests/<tag>` request URLs from it.
///
/// Returns `None` when the reference lacks the canonical prefix, or when
/// what follows is not a legal OCI tag — so a reference carrying a second
/// `:`, an `@digest`, a path separator, or an over-long tag is rejected
/// here rather than becoming a request URL that can only 404.
#[must_use]
pub fn oci_reference_tag(reference: &str) -> Option<&str> {
    let tag = reference.strip_prefix(GHCR_BASE)?.strip_prefix(':')?;
    is_oci_tag(tag).then_some(tag)
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

/// `sha256:<hex>` of `bytes` — the OCI digest form manifests and blobs are
/// addressed by (`manifests/<digest>`, `blobs/<digest>`).
#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

/// Content addressed by a digest did not hash to it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("OCI digest mismatch: expected {expected}, content hashes to {actual}")]
pub struct OciDigestMismatch {
    /// The digest the content was addressed by.
    pub expected: String,
    /// The digest the content actually hashes to.
    pub actual: String,
}

/// Verify that `bytes` hash to the `sha256:<hex>` `expected` digest.
///
/// A digest reference is only as trustworthy as the content behind it —
/// registries can serve inconsistent bytes, so a fetch by
/// `manifests/<digest>` must recompute and compare rather than assume.
///
/// # Errors
///
/// [`OciDigestMismatch`] carrying both digests when they differ.
pub fn verify_oci_digest(bytes: &[u8], expected: &str) -> Result<(), OciDigestMismatch> {
    let actual = sha256_digest(bytes);
    if actual != expected {
        return Err(OciDigestMismatch {
            expected: expected.to_owned(),
            actual,
        });
    }
    Ok(())
}

/// Compute the OCI reference for an artifact.
///
/// Format: `ghcr.io/water-rs/stow-cache:{name}.{version}-{target_short}-{rustc_short}-{feat_hash}-{c_metadata}{kind_suffix}`
///
/// Every artifact is a tag of the single `water-rs/stow-cache` package; the
/// crate name is the tag's first `.`-separated segment, so
/// `sha-1.0.10.0-…` is crate `sha-1`, version `0.10.0`.
///
/// Tags are capped at [`MAX_OCI_TAG_LEN`]. Short forms for target and rustc
/// and a short hash of the feature set keep a typical tag near 50 characters
/// after the crate name, but neither the crate name (up to 128 by
/// [`crate::identity::CrateName`]) nor a semver prerelease is bounded
/// tightly enough to guarantee that, so the readable `{name}.{version}` head
/// is truncated to whatever the tail leaves. The tail is what carries
/// identity — `c_metadata` is a prefix of the blake3 compile key over the
/// whole five-element identity — so a truncated head can never make two
/// artifacts share a tag.
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

    let tail = format!("-{target_short}-{rustc_short}-{feat_hash}-{c_metadata}{kind_suffix}");
    let mut head = format!("{name}.{version}");
    // Every component is ASCII by construction — crate names are
    // `[A-Za-z0-9_-]` and `sanitize_oci_tag_component` maps anything else to
    // `_` — so truncating by bytes cannot split a character. The budget
    // reserves room for [`BUNDLE_TAG_SUFFIX`], so the bundle tag derived by
    // [`bundle_oci_reference`] fits the same limit.
    head.truncate(MAX_OCI_TAG_LEN.saturating_sub(tail.len() + BUNDLE_TAG_SUFFIX.len()));
    format!("{GHCR_BASE}:{head}{tail}")
}

/// The reference of the assembled bundle artifact published for a canonical
/// stow `oci_reference`: the same repository, the tag with
/// [`BUNDLE_TAG_SUFFIX`] appended.
///
/// Returns `None` when `reference` is not a canonical stow reference or the
/// suffixed tag would exceed [`MAX_OCI_TAG_LEN`]; [`oci_reference`] reserves
/// the suffix in its budget, so every reference it produced fits.
#[must_use]
pub fn bundle_oci_reference(reference: &str) -> Option<String> {
    let tag = oci_reference_tag(reference)?;
    let bundle_tag = format!("{tag}{BUNDLE_TAG_SUFFIX}");
    is_oci_tag(&bundle_tag).then(|| format!("{GHCR_BASE}:{bundle_tag}"))
}

/// The crate segment stays lowercase even though OCI tags are
/// case-sensitive and crate names need not be (`Inflector`, `RustyXML`, …).
/// crates.io already rejects a new name that differs from a published one
/// only by case (or by `-` vs `_`), so folding case cannot make two distinct
/// published crates collide on one tag prefix.
fn crate_tag_segment(name: &str) -> String {
    name.to_ascii_lowercase()
}

pub(crate) fn sanitize_oci_tag_component(value: &str) -> String {
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
                strip: crate::platform::StripLevel::None,
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
                strip: crate::platform::StripLevel::None,
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
                strip: crate::platform::StripLevel::None,
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
                strip: crate::platform::StripLevel::None,
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

    /// The worst case the identity newtypes admit: a 128-char crate name
    /// and a long prerelease. The head gives way, the identity-bearing tail
    /// survives whole, and the tag stays a legal OCI tag.
    #[test]
    fn a_long_name_and_prerelease_truncate_the_head_not_the_identity() {
        let key = ArtifactKey {
            crate_id: CrateId {
                name: "x".repeat(128),
                version: semver::Version::parse("1.0.0-alpha.20260918.build-candidate.7")
                    .expect("prerelease version"),
            },
            features: FeatureSet(BTreeSet::from(["derive".into()])),
            crate_types: vec![RustCrateType::Rlib],
            target: Target("x86_64-pc-windows-msvc".into()),
            rustc_version: RustcVersion {
                version: semver::Version::parse("1.93.0-beta.5").expect("beta version"),
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
            kind: ArtifactKind::ProcMacro,
        };

        let reference = oci_reference(&key, "fedcba9876543210");
        let tag = oci_reference_tag(&reference).expect("a legal, canonical tag");
        // The head leaves exactly the room the bundle suffix needs, so both
        // tags of the artifact are legal.
        assert_eq!(tag.len(), MAX_OCI_TAG_LEN - BUNDLE_TAG_SUFFIX.len());
        assert!(tag.ends_with("-fedcba9876543210-pm"), "{tag}");
        assert!(tag.starts_with("xxxx"), "{tag}");
        let bundle = bundle_oci_reference(&reference).expect("bundle tag fits");
        let bundle_tag = bundle
            .rsplit_once(':')
            .map(|(_, tag)| tag)
            .expect("bundle reference has a tag");
        assert_eq!(bundle_tag.len(), MAX_OCI_TAG_LEN);
        assert_eq!(bundle_tag, format!("{tag}{BUNDLE_TAG_SUFFIX}"));
    }

    /// A tag the builder never emits must not be accepted as canonical: the
    /// edge turns it into a `/manifests/<tag>` URL, and the register path
    /// gates on the same parser.
    #[test]
    fn illegal_tags_are_not_canonical_references() {
        let over_long = format!("{GHCR_BASE}:s.{}", "1".repeat(MAX_OCI_TAG_LEN));
        for reference in [
            // A second `:` — a tag cannot contain one.
            "ghcr.io/water-rs/stow-cache:serde.1.0.0:extra",
            // A digest form, not a tag.
            "ghcr.io/water-rs/stow-cache:sha256@abc",
            // A path separator, which would escape the manifests URL.
            "ghcr.io/water-rs/stow-cache:serde.1.0.0/../../evil",
            // A tag may not start with `.` or `-`.
            "ghcr.io/water-rs/stow-cache:.serde.1.0.0",
            over_long.as_str(),
        ] {
            assert_eq!(oci_reference_tag(reference), None, "{reference}");
            assert_eq!(oci_reference_name(reference), None, "{reference}");
        }
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
                strip: crate::platform::StripLevel::None,
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
    fn content_hashing_to_the_digest_verifies() {
        let bytes =
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#;
        let digest = sha256_digest(bytes);
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), "sha256:".len() + 64);
        verify_oci_digest(bytes, &digest).expect("content hashes to its digest");
    }

    #[test]
    fn content_hashing_to_a_different_digest_is_rejected() {
        let registered = sha256_digest(b"the manifest the row was registered for");
        let error = verify_oci_digest(b"repushed manifest bytes", &registered)
            .expect_err("content not hashing to the expected digest must fail");
        assert_eq!(error.expected, registered);
        assert_eq!(error.actual, sha256_digest(b"repushed manifest bytes"));
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
                strip: crate::platform::StripLevel::None,
            },
            kind: ArtifactKind::Rlib,
        };

        let reference = oci_reference(&key, "d44626168446442d");
        let tag = reference.rsplit_once(':').expect("tag separator").1;
        assert!(tag.contains("0.17.0_1.8.1"));
        assert!(!tag.contains('+'));
    }
}
