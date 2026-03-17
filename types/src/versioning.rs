use semver::Version;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SemverBreakingLine {
    StableMajor(u64),
    PreOneMinor(u64),
    PreZeroPatch(u64),
}

pub fn is_semver_compatible_upgrade(current: &Version, candidate: &Version) -> bool {
    if candidate <= current {
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

pub fn breaking_line(version: &Version) -> SemverBreakingLine {
    if version.major != 0 {
        return SemverBreakingLine::StableMajor(version.major);
    }
    if version.minor != 0 {
        return SemverBreakingLine::PreOneMinor(version.minor);
    }

    SemverBreakingLine::PreZeroPatch(version.patch)
}

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
        let known = vec![
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
