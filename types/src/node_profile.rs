//! The named build profiles a node compiles under (stow#1008).
//!
//! A node's profile is a field of its identity, so a task id, the
//! scheduler's node and the builder's cargo invocation all read the same
//! value. This module is the one place a profile is defined: its name,
//! the task-id segment it contributes and the cargo arguments that
//! select it. Caching another profile's builds adds a value here, not a
//! mechanism anywhere else.

use std::fmt;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::platform::{PanicStrategy, Profile};

/// A named profile one node is built under.
///
/// The profile names cargo's own `unit.profile.name` for the unit, so the
/// side-specific `build-override` a host unit compiles under is the
/// profile's cargo default and is never a separate value.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum NodeProfile {
    /// Cargo's `dev` profile — what every published node is built under.
    #[default]
    Dev,
    /// Cargo's `release` profile.
    Release,
}

impl NodeProfile {
    /// Every defined profile.
    pub const ALL: [Self; 2] = [Self::Dev, Self::Release];

    /// The profile's name — cargo's profile name and the wire spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Release => "release",
        }
    }

    /// The profile's position in [`Self::ALL`] — the compact form a
    /// bit-packed holder stores.
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        self as u8
    }

    /// The profile at `ordinal` in [`Self::ALL`], `None` past the last.
    #[must_use]
    pub const fn from_ordinal(ordinal: u8) -> Option<Self> {
        match ordinal {
            0 => Some(Self::Dev),
            1 => Some(Self::Release),
            _ => None,
        }
    }

    /// The profile named `name`.
    ///
    /// # Errors
    /// Fails for a name no profile is defined for.
    pub fn parse(name: &str) -> crate::error::Result<Self> {
        Self::ALL
            .into_iter()
            .find(|profile| profile.name() == name)
            .ok_or_else(|| {
                crate::stow_error!(
                    "profile `{name}` is not one stow defines (known: {})",
                    Self::ALL.map(Self::name).join(", ")
                )
            })
    }

    /// Whether this is [`Self::Dev`] — the profile whose task ids carry
    /// no profile segment.
    #[must_use]
    pub const fn is_dev(&self) -> bool {
        matches!(self, Self::Dev)
    }

    /// The task-id segment this profile appends, `None` for [`Self::Dev`]
    /// so every dev id keeps the shape it had before profiles were part
    /// of the identity.
    #[must_use]
    pub const fn id_segment(self) -> Option<&'static str> {
        match self {
            Self::Dev => None,
            Self::Release => Some("release"),
        }
    }

    /// The cargo arguments that select this profile for a build.
    #[must_use]
    pub const fn cargo_args(self) -> &'static [&'static str] {
        self.definition().cargo_args
    }

    /// The settings a unit of this profile compiles with on the target
    /// side.
    #[must_use]
    pub const fn target_settings(self) -> ProfileSettings {
        self.definition().target
    }

    /// The settings a host unit (build script, proc macro and their
    /// dependencies) compiles with: cargo's default `build-override` of
    /// this profile, which stow does not change.
    #[must_use]
    pub const fn host_settings(self) -> ProfileSettings {
        self.definition().host
    }

    /// The named profile a unit compiled with `profile` belongs to, `None`
    /// when its settings are none of the defined profiles' — a custom
    /// profile with other settings has no node and is served from the
    /// local cache only. A unit whose settings equal the target settings
    /// or the host settings of a profile belongs to it, so a host unit
    /// cargo merged into the target compile resolves the same way.
    #[must_use]
    pub fn of(profile: &Profile) -> Option<Self> {
        Self::ALL.into_iter().find(|candidate| {
            candidate.target_settings().matches(profile)
                || candidate.host_settings().matches(profile)
        })
    }

    /// The one definition of this profile: the builder's cargo arguments
    /// and the settings those arguments make cargo state for its units.
    const fn definition(self) -> &'static Definition {
        match self {
            Self::Dev => &DEV,
            Self::Release => &RELEASE,
        }
    }
}

/// The compile settings that tell one named profile's units from another's.
///
/// `strip` is not among them: it acts at link time only, and the cache
/// pins it to none for libraries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileSettings {
    /// `-C opt-level`.
    pub opt_level: &'static str,
    /// Debug info level: 0 none, 1 line tables, 2 full.
    pub debuginfo: u32,
    /// `-C debug-assertions`.
    pub debug_assertions: bool,
    /// `-C overflow-checks`.
    pub overflow_checks: bool,
    /// `-C panic`.
    pub panic: PanicStrategy,
}

impl ProfileSettings {
    /// Whether `profile` states exactly these settings.
    #[must_use]
    pub fn matches(&self, profile: &Profile) -> bool {
        profile.opt_level == self.opt_level
            && profile.debuginfo == self.debuginfo
            && profile.debug_assertions == self.debug_assertions
            && profile.overflow_checks == self.overflow_checks
            && profile.panic == self.panic
    }
}

/// One profile's definition. Values are cargo's documented defaults
/// (<https://doc.rust-lang.org/cargo/reference/profiles.html>): `dev` is
/// opt-level 0, full debuginfo, debug assertions and overflow checks on;
/// `release` is opt-level 3, no debuginfo, both checks off; `panic` is
/// unwind in both. A profile's default `build-override` is opt-level 0
/// with no debuginfo and inherits the profile's two checks.
struct Definition {
    cargo_args: &'static [&'static str],
    target: ProfileSettings,
    host: ProfileSettings,
}

const DEV: Definition = Definition {
    cargo_args: &[],
    target: ProfileSettings {
        opt_level: "0",
        debuginfo: 2,
        debug_assertions: true,
        overflow_checks: true,
        panic: PanicStrategy::Unwind,
    },
    host: ProfileSettings {
        opt_level: "0",
        debuginfo: 0,
        debug_assertions: true,
        overflow_checks: true,
        panic: PanicStrategy::Unwind,
    },
};

const RELEASE: Definition = Definition {
    cargo_args: &["--release"],
    target: ProfileSettings {
        opt_level: "3",
        debuginfo: 0,
        debug_assertions: false,
        overflow_checks: false,
        panic: PanicStrategy::Unwind,
    },
    host: ProfileSettings {
        opt_level: "0",
        debuginfo: 0,
        debug_assertions: false,
        overflow_checks: false,
        panic: PanicStrategy::Unwind,
    },
};

impl fmt::Display for NodeProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::NodeProfile;

    /// Every defined profile round-trips through its name and carries a
    /// distinct id segment.
    #[test]
    fn every_profile_round_trips_and_keys_apart() {
        let mut segments = std::collections::BTreeSet::new();
        for profile in NodeProfile::ALL {
            assert_eq!(NodeProfile::parse(profile.name()).unwrap(), profile);
            assert_eq!(
                serde_json::to_string(&profile).unwrap(),
                format!("\"{}\"", profile.name())
            );
            assert!(segments.insert(profile.id_segment()), "{profile}");
            assert_eq!(NodeProfile::from_ordinal(profile.ordinal()), Some(profile));
        }
        assert_eq!(NodeProfile::default(), NodeProfile::Dev);
        assert!(NodeProfile::Dev.id_segment().is_none());
        assert!(NodeProfile::parse("bench").is_err());
    }

    fn profile(settings: super::ProfileSettings) -> crate::platform::Profile {
        crate::platform::Profile {
            opt_level: settings.opt_level.to_owned(),
            debuginfo: settings.debuginfo,
            debug_assertions: settings.debug_assertions,
            overflow_checks: settings.overflow_checks,
            panic: settings.panic,
            strip: crate::platform::StripLevel::None,
        }
    }

    /// Each profile's target and host settings classify as that profile,
    /// and any other settings have no named profile.
    #[test]
    fn units_classify_by_their_settings() {
        for named in NodeProfile::ALL {
            assert_eq!(
                NodeProfile::of(&profile(named.target_settings())),
                Some(named)
            );
            assert_eq!(
                NodeProfile::of(&profile(named.host_settings())),
                Some(named)
            );
        }
        let mut tuned = profile(NodeProfile::Dev.target_settings());
        tuned.opt_level = "1".to_owned();
        assert_eq!(NodeProfile::of(&tuned), None);
        let mut abort = profile(NodeProfile::Release.target_settings());
        abort.panic = crate::platform::PanicStrategy::Abort;
        assert_eq!(NodeProfile::of(&abort), None);
    }
}
