//! Identity of the GitHub Actions workflows whose signatures the CLI trusts.
//!
//! The scheduler dispatches production workflows on the deployed edge's own
//! release tag ([`RELEASE_TAG`]), and a verifier accepts a Fulcio certificate
//! only when its subject is a trusted workflow file at a release tag
//! (`@refs/tags/v<MAJOR>.<MINOR>.<PATCH>`). Spelling each piece once keeps the
//! two ends from drifting apart.

use std::fmt;
use std::str::FromStr;

/// `concat!` needs literals, hence the macros.
macro_rules! repository {
    () => {
        "water-rs/stow"
    };
}

/// GitHub repository (`owner/name`) that hosts the trusted build workflow.
pub const REPOSITORY: &str = repository!();
/// Workflow file under `.github/workflows/` that performs trusted builds.
pub const WORKFLOW_FILE: &str = "build-crate.yml";
/// The `name:` the trusted workflow declares.
///
/// GitHub shows it as a run's `display_title` until it has rendered the
/// workflow's `run-name`, so a reader that meets it is looking at a run
/// whose title is not known yet, not at another workflow's run
/// (stow#704).
pub const WORKFLOW_NAME: &str = "build-crate";
/// OIDC issuer of GitHub Actions job tokens.
pub const CERTIFICATE_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Workflow file under `.github/workflows/` that publishes and signs the
/// artifact indexes.
pub const INDEX_WORKFLOW_FILE: &str = "index-publish.yml";
/// Workflow file under `.github/workflows/` that resolves an admitted
/// human request and submits its outcome (stow#428).
///
/// The scheduler dispatches request resolutions to exactly this
/// workflow on exactly [`RELEASE_TAG`] — the same arm [`WORKFLOW_FILE`] has
/// for build tasks.
pub const RESOLVE_WORKFLOW_FILE: &str = "resolve-request.yml";
/// Workflow file under `.github/workflows/` that resolves a preheat
/// wave and submits its trees (stow#880).
///
/// The scheduler dispatches a new stable rustc's preheat to exactly
/// this workflow on exactly [`RELEASE_TAG`]; the workflow confirms the
/// version against the official channel manifest before resolving.
pub const PREHEAT_WORKFLOW_FILE: &str = "preheat-admin.yml";

/// The release tag of this build: `v` and the workspace version.
///
/// The edge dispatches every production workflow on its own tag, and the
/// CLI trusts any release tag by prefix ([`RELEASE_REF_PREFIX`]).
pub const RELEASE_TAG: &str = concat!("v", env!("CARGO_PKG_VERSION"));

/// What every release tag ref begins with; a trusted certificate subject is
/// `…@refs/tags/v` followed by `MAJOR.MINOR.PATCH`.
pub const RELEASE_REF_PREFIX: &str = "refs/tags/v";

/// A release tag: `v` followed by a strict `MAJOR.MINOR.PATCH`, with no
/// pre-release, build metadata, leading zero or extra component.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReleaseTag(String);

/// A string that is not a [`ReleaseTag`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a release tag (`v` and a strict MAJOR.MINOR.PATCH)")]
pub struct ReleaseTagError(String);

impl ReleaseTag {
    /// The tag of this build ([`RELEASE_TAG`]).
    ///
    /// # Panics
    ///
    /// When the workspace version is not a plain `MAJOR.MINOR.PATCH`; a
    /// release is cut only from such a version.
    #[must_use]
    pub fn current() -> Self {
        RELEASE_TAG
            .parse()
            .expect("the workspace version is a plain MAJOR.MINOR.PATCH")
    }

    /// The tag name, e.g. `v0.20.0`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The full ref, e.g. `refs/tags/v0.20.0`.
    #[must_use]
    pub fn git_ref(&self) -> String {
        format!("refs/tags/{}", self.0)
    }
}

impl FromStr for ReleaseTag {
    type Err = ReleaseTagError;

    fn from_str(tag: &str) -> Result<Self, Self::Err> {
        let error = || ReleaseTagError(tag.to_owned());
        let version = tag.strip_prefix('v').ok_or_else(error)?;
        let plain = |part: &str| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == "0" || !part.starts_with('0'))
                && part.parse::<u64>().is_ok()
        };
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() == 3 && parts.iter().all(|part| plain(part)) {
            Ok(Self(tag.to_owned()))
        } else {
            Err(error())
        }
    }
}

impl fmt::Display for ReleaseTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One trusted workflow file. Its certificate subject is
/// `https://github.com/<repository>/.github/workflows/<file>@refs/tags/<tag>`
/// for the release tag the run executes at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedWorkflow {
    file: &'static str,
}

impl TrustedWorkflow {
    /// The trusted build workflow ([`WORKFLOW_FILE`]).
    pub const BUILD: Self = Self::new(WORKFLOW_FILE);
    /// The index-publish workflow ([`INDEX_WORKFLOW_FILE`]).
    pub const INDEX: Self = Self::new(INDEX_WORKFLOW_FILE);

    /// A workflow file under `.github/workflows/`.
    #[must_use]
    pub const fn new(file: &'static str) -> Self {
        Self { file }
    }

    /// The workflow file name.
    #[must_use]
    pub const fn file(self) -> &'static str {
        self.file
    }

    /// The certificate subject up to and including `@`, the part every
    /// release tag shares.
    #[must_use]
    pub fn san_stem(self) -> String {
        format!(
            "https://github.com/{REPOSITORY}/.github/workflows/{}@",
            self.file
        )
    }

    /// The certificate subject prefix every release of this workflow
    /// shares: [`Self::san_stem`] and [`RELEASE_REF_PREFIX`].
    #[must_use]
    pub fn san_prefix(self) -> String {
        format!("{}{RELEASE_REF_PREFIX}", self.san_stem())
    }

    /// The exact certificate subject of this workflow run at `tag`.
    #[must_use]
    pub fn san(self, tag: &ReleaseTag) -> String {
        format!("{}{}", self.san_stem(), tag.git_ref())
    }

    /// Whether `san` is this workflow at some release tag: the prefix, then
    /// a strict `MAJOR.MINOR.PATCH` and nothing else.
    #[must_use]
    pub fn matches(self, san: &str) -> bool {
        san.strip_prefix(self.san_stem().as_str())
            .and_then(|git_ref| git_ref.strip_prefix("refs/tags/"))
            .is_some_and(|tag| tag.parse::<ReleaseTag>().is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::{RELEASE_TAG, ReleaseTag, TrustedWorkflow};

    #[test]
    fn a_release_tag_is_v_and_a_strict_semver_triple() {
        for good in ["v0.0.0", "v1.2.3", "v10.20.30"] {
            assert!(
                good.parse::<ReleaseTag>().is_ok(),
                "{good} is a release tag"
            );
        }
        for bad in [
            "",
            "v",
            "1.2.3",
            "v1.2",
            "v1.2.3.4",
            "v1.2.3x",
            "v1.2.3-rc.1",
            "v1.2.3+b",
            "v01.2.3",
            "v1.2.03",
            "v-1.2.3",
            "v1.2.+3",
            "v 1.2.3",
            "V1.2.3",
            "oci/v1.2.3",
            "stow-cli-v1.2.3",
            "v1..3",
            "v99999999999999999999.0.0",
        ] {
            assert!(
                bad.parse::<ReleaseTag>().is_err(),
                "{bad:?} is not a release tag"
            );
        }
    }

    #[test]
    fn the_build_of_this_crate_has_a_release_tag() {
        assert_eq!(ReleaseTag::current().as_str(), RELEASE_TAG);
    }

    #[test]
    fn the_subject_composes_repository_workflow_and_tag() {
        let tag: ReleaseTag = "v1.2.3".parse().unwrap();
        assert_eq!(
            TrustedWorkflow::BUILD.san(&tag),
            "https://github.com/water-rs/stow/.github/workflows/build-crate.yml@refs/tags/v1.2.3"
        );
        assert_eq!(
            TrustedWorkflow::INDEX.san_prefix(),
            "https://github.com/water-rs/stow/.github/workflows/index-publish.yml@refs/tags/v"
        );
    }

    #[test]
    fn only_the_release_tag_prefix_of_the_workflow_matches() {
        let build = TrustedWorkflow::BUILD;
        let at =
            |suffix: &str| format!("https://github.com/water-rs/stow/.github/workflows/{suffix}");
        assert!(build.matches(&at("build-crate.yml@refs/tags/v1.2.3")));
        for bad in [
            "build-crate.yml@refs/heads/main",
            "build-crate.yml@refs/tags/stow-cli-v1.2.3",
            "build-crate.yml@refs/tags/oci/v1.2.3",
            "build-crate.yml@refs/tags/v1.2",
            "build-crate.yml@refs/tags/v1.2.3x",
            "build-crate.yml@refs/tags/v1.2.3/extra",
            "index-publish.yml@refs/tags/v1.2.3",
            "build-crate.yml.bak@refs/tags/v1.2.3",
        ] {
            assert!(!build.matches(&at(bad)), "{bad} must be refused");
        }
        assert!(!build.matches(
            "https://github.com/water-rs/other/.github/workflows/build-crate.yml@refs/tags/v1.2.3"
        ));
    }
}
