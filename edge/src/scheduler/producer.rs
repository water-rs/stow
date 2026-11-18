//! The producer check of the anonymous submit lane (stow#1605): only
//! the stow CLI submits there, identified by its
//! `User-Agent: stow-cli/<version> (<os>)`, and a CLI older than the
//! operator's minimum version submits trees no build can reproduce.

use semver::Version;

/// Why a submission's producer is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProducerRefusal {
    /// The `User-Agent` does not identify a stow CLI release.
    #[error(
        "this request does not identify a stow CLI version; update stow to {minimum} or newer \
         so your cache misses get queued"
    )]
    Unidentified {
        /// The minimum version in force.
        minimum: Version,
    },
    /// The CLI is older than the minimum version.
    #[error(
        "stow {found} is too old to report cache misses; update stow to {minimum} or newer \
         so your cache misses get queued"
    )]
    Outdated {
        /// The version the `User-Agent` named.
        found: Version,
        /// The minimum version in force.
        minimum: Version,
    },
}

/// Admit a submission whose `User-Agent` names a CLI of at least
/// `minimum`.
///
/// # Errors
/// [`ProducerRefusal::Unidentified`] when the header is missing or its
/// version does not parse, [`ProducerRefusal::Outdated`] when the
/// version is below `minimum`.
pub fn check(user_agent: Option<&str>, minimum: &Version) -> Result<(), ProducerRefusal> {
    let (version, _os) = crate::stats::user_agent_dimensions(user_agent);
    let found = Version::parse(version).map_err(|_| ProducerRefusal::Unidentified {
        minimum: minimum.clone(),
    })?;
    if found < *minimum {
        return Err(ProducerRefusal::Outdated {
            found,
            minimum: minimum.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ProducerRefusal, check};
    use crate::scheduler::queue::DEFAULT_MIN_CLI_VERSION;
    use semver::Version;

    /// stow#1605: a CLI below the minimum is refused, naming both
    /// versions.
    #[test]
    fn a_cli_below_the_minimum_is_refused() {
        let refusal = check(Some("stow-cli/0.21.6 (linux)"), &DEFAULT_MIN_CLI_VERSION)
            .expect_err("0.21.6 is below 0.21.7");
        assert_eq!(
            refusal,
            ProducerRefusal::Outdated {
                found: Version::new(0, 21, 6),
                minimum: DEFAULT_MIN_CLI_VERSION,
            }
        );
        assert!(refusal.to_string().contains("update stow"));
    }

    /// The minimum itself and anything above it pass; a prerelease of
    /// the minimum orders below it.
    #[test]
    fn a_cli_at_or_above_the_minimum_passes() {
        for agent in [
            "stow-cli/0.21.7 (macos)",
            "stow-cli/0.21.8 (linux)",
            "stow-cli/0.22.0 (windows)",
            "stow-cli/1.0.0",
        ] {
            assert_eq!(
                check(Some(agent), &DEFAULT_MIN_CLI_VERSION),
                Ok(()),
                "{agent}"
            );
        }
        assert!(
            check(
                Some("stow-cli/0.21.7-rc.1 (linux)"),
                &DEFAULT_MIN_CLI_VERSION
            )
            .is_err()
        );
    }

    /// A missing header, a foreign agent and an unparsable version are
    /// refused the same way — only the CLI calls the lane.
    #[test]
    fn a_missing_or_foreign_user_agent_is_refused() {
        for agent in [
            None,
            Some(""),
            Some("curl/8.4.0"),
            Some("stow-cli/latest (linux)"),
        ] {
            assert_eq!(
                check(agent, &DEFAULT_MIN_CLI_VERSION),
                Err(ProducerRefusal::Unidentified {
                    minimum: DEFAULT_MIN_CLI_VERSION,
                }),
                "{agent:?}"
            );
        }
    }

    /// An operator's raise or lowering changes the verdict with no
    /// deploy: the minimum is an argument read from the graph.
    #[test]
    fn the_minimum_in_force_decides_the_verdict() {
        let agent = Some("stow-cli/0.21.7 (linux)");
        assert_eq!(check(agent, &Version::new(0, 21, 7)), Ok(()));
        assert!(check(agent, &Version::new(0, 22, 0)).is_err());
        assert_eq!(
            check(Some("stow-cli/0.20.0 (linux)"), &Version::new(0, 1, 0)),
            Ok(())
        );
    }
}
