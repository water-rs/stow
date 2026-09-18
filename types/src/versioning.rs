//! Semver reasoning for cache coverage: which upgrade a client may accept
//! silently, and which breaking line a version belongs to.

use semver::Version;
use serde::{Deserialize, Serialize};

/// The semver breaking line a version belongs to.
///
/// Cargo's `^` rules make versions within one line interchangeable: `1.x`
/// shares a line across minor and patch, `0.x.y` shares only the patch for
/// `0.0.x`, and `0.x` shares the minor line.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SemverBreakingLine {
    /// `major >= 1`: the major version number.
    StableMajor(u64),
    /// `0.x.y` with `x >= 1`: the minor version number.
    PreOneMinor(u64),
    /// `0.0.y`: the patch version number.
    PreZeroPatch(u64),
}

/// Whether `candidate` may replace `current` under cargo's `^` compatibility
/// rules: strictly newer, on the same breaking line, and not a pre-release.
#[must_use]
pub fn is_semver_compatible_upgrade(current: &Version, candidate: &Version) -> bool {
    if candidate <= current {
        return false;
    }
    // Cargo's `^req` never resolves to a pre-release the user did not pin
    // explicitly; serving one would inject code the user's own resolution
    // could never produce.
    if !candidate.pre.is_empty() {
        return false;
    }

    if current.major != 0 {
        return candidate.major == current.major;
    }
    if current.minor != 0 {
        return candidate.major == 0 && candidate.minor == current.minor;
    }

    candidate.major == 0 && candidate.minor == 0 && candidate.patch == current.patch
}

/// The breaking line `version` belongs to.
#[must_use]
pub const fn breaking_line(version: &Version) -> SemverBreakingLine {
    if version.major != 0 {
        return SemverBreakingLine::StableMajor(version.major);
    }
    if version.minor != 0 {
        return SemverBreakingLine::PreOneMinor(version.minor);
    }

    SemverBreakingLine::PreZeroPatch(version.patch)
}

/// Whether `candidate`'s breaking line is among the `limit` most recent
/// distinct breaking lines in `known_versions` (ordered by the newest version
/// in each line).
///
/// Stow only prebuilds the most recent breaking lines; a candidate outside
/// the window is a miss the scheduler does not chase.
pub fn is_within_recent_breaking_lines<'a>(
    candidate: &Version,
    known_versions: impl IntoIterator<Item = &'a Version>,
    limit: usize,
) -> bool {
    if limit == 0 {
        return false;
    }

    let mut versions = known_versions.into_iter().cloned().collect::<Vec<_>>();
    versions.sort_by(|left, right| right.cmp(left));

    let candidate_line = breaking_line(candidate);
    let mut lines = Vec::<SemverBreakingLine>::new();
    for version in versions {
        let line = breaking_line(&version);
        if lines.iter().any(|known| known == &line) {
            continue;
        }
        lines.push(line);
        if lines.len() == limit {
            break;
        }
    }

    lines.iter().any(|line| line == &candidate_line)
}

#[cfg(test)]
mod tests {
    use super::{
        SemverBreakingLine, breaking_line, is_semver_compatible_upgrade,
        is_within_recent_breaking_lines,
    };

    fn version(raw: &str) -> semver::Version {
        semver::Version::parse(raw).unwrap()
    }

    #[test]
    fn semver_compatibility_matches_cargo_major_rules() {
        assert!(is_semver_compatible_upgrade(
            &version("1.2.3"),
            &version("1.9.0")
        ));
        assert!(!is_semver_compatible_upgrade(
            &version("1.2.3"),
            &version("2.0.0")
        ));
        assert!(is_semver_compatible_upgrade(
            &version("0.9.1"),
            &version("0.9.7")
        ));
        assert!(!is_semver_compatible_upgrade(
            &version("0.9.1"),
            &version("0.10.0")
        ));
        assert!(!is_semver_compatible_upgrade(
            &version("0.0.5"),
            &version("0.0.6")
        ));
    }

    #[test]
    fn pre_release_candidates_are_never_compatible_upgrades() {
        assert!(!is_semver_compatible_upgrade(
            &version("1.4.3"),
            &version("1.5.0-rc.1")
        ));
        assert!(!is_semver_compatible_upgrade(
            &version("0.9.1"),
            &version("0.9.7-beta.2")
        ));
    }

    #[test]
    fn breaking_lines_follow_semver_boundaries() {
        assert_eq!(
            breaking_line(&version("3.2.1")),
            SemverBreakingLine::StableMajor(3)
        );
        assert_eq!(
            breaking_line(&version("0.9.4")),
            SemverBreakingLine::PreOneMinor(9)
        );
        assert_eq!(
            breaking_line(&version("0.0.7")),
            SemverBreakingLine::PreZeroPatch(7)
        );
    }

    #[test]
    fn recent_breaking_line_window_ignores_older_lines() {
        let known = [
            version("3.0.2"),
            version("2.4.1"),
            version("1.9.9"),
            version("0.8.7"),
        ];
        assert!(is_within_recent_breaking_lines(
            &version("3.0.2"),
            known.iter(),
            3
        ));
        assert!(is_within_recent_breaking_lines(
            &version("2.4.1"),
            known.iter(),
            3
        ));
        assert!(is_within_recent_breaking_lines(
            &version("1.9.9"),
            known.iter(),
            3
        ));
        assert!(!is_within_recent_breaking_lines(
            &version("0.8.7"),
            known.iter(),
            3
        ));
    }
}
