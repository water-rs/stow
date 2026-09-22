//! Toolchain and target descriptions: target triples, rustc versions,
//! compile profiles, and panic strategy.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Compilation target triple (e.g., "x86_64-unknown-linux-gnu").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Target(pub String);

impl Target {
    /// Short form for use in OCI tags (e.g., "x86_64-linux" from "x86_64-unknown-linux-gnu").
    #[must_use]
    pub fn short(&self) -> String {
        let parts: Vec<&str> = self.0.split('-').collect();
        match parts.as_slice() {
            [arch, _vendor, os, ..] => format!("{arch}-{os}"),
            [arch, os] => format!("{arch}-{os}"),
            _ => self.0.clone(),
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Identifies the exact rustc toolchain used for compilation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RustcVersion {
    /// Semantic version (e.g., 1.83.0)
    pub version: semver::Version,
    /// Short commit hash from `rustc --version --verbose`
    pub commit_hash: String,
    /// LLVM version string (e.g., "19.1.4")
    pub llvm_version: String,
}

impl RustcVersion {
    /// Short form for OCI tags: "1.83.0"
    #[must_use]
    pub fn short(&self) -> String {
        self.version.to_string()
    }
}

impl fmt::Display for RustcVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.version, self.commit_hash)
    }
}

/// Compilation profile settings observed from actual rustc arguments.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Profile {
    /// `-C opt-level` value as rustc saw it (`"0"`–`"3"`, `"s"`, `"z"`).
    pub opt_level: String,
    /// Debug info level normalized to 0 (none), 1 (line tables), or 2 (full).
    pub debuginfo: u32,
    /// Whether `-C debug-assertions` was enabled.
    pub debug_assertions: bool,
    /// Whether `-C overflow-checks` was enabled.
    pub overflow_checks: bool,
    /// `-C panic` strategy.
    pub panic: PanicStrategy,
    /// `-C strip` level. Stripping happens at link time, so it only changes
    /// the bytes of linked artifacts; `normalized_cache_profile` pins it to
    /// `None` for rlibs. The canonical JSON omits `none`, which is the only
    /// level artifacts registered before the field existed could carry.
    #[serde(default, skip_serializing_if = "StripLevel::is_none")]
    pub strip: StripLevel,
}

impl Profile {
    /// Name the fields that differ between a cached artifact's profile
    /// (`self`) and the one a compile requests, as two parallel `k=v`
    /// lists. `None` when the two profiles are equal.
    ///
    /// A cached artifact only serves a compile that asks for the same
    /// profile, so a machine whose `[profile.dev]` diverges from the one
    /// the public cache is built with gets no hits at all. Which knob
    /// diverged is the whole diagnosis, and nothing downstream can
    /// reconstruct it.
    #[must_use]
    pub fn divergence(&self, requested: &Self) -> Option<(String, String)> {
        let mut cached = Vec::new();
        let mut wanted = Vec::new();
        let mut note = |field: &str, mine: String, theirs: String| {
            if mine != theirs {
                cached.push(format!("{field}={mine}"));
                wanted.push(format!("{field}={theirs}"));
            }
        };
        note(
            "opt-level",
            self.opt_level.clone(),
            requested.opt_level.clone(),
        );
        note(
            "debuginfo",
            self.debuginfo.to_string(),
            requested.debuginfo.to_string(),
        );
        note(
            "debug-assertions",
            self.debug_assertions.to_string(),
            requested.debug_assertions.to_string(),
        );
        note(
            "overflow-checks",
            self.overflow_checks.to_string(),
            requested.overflow_checks.to_string(),
        );
        note(
            "panic",
            format!("{:?}", self.panic).to_lowercase(),
            format!("{:?}", requested.panic).to_lowercase(),
        );
        note(
            "strip",
            format!("{:?}", self.strip).to_lowercase(),
            format!("{:?}", requested.strip).to_lowercase(),
        );
        if cached.is_empty() {
            return None;
        }
        Some((cached.join(", "), wanted.join(", ")))
    }

    /// Returns true if this is a debug profile (`opt_level` "0" with `debug_assertions`).
    #[must_use]
    pub fn is_debug(&self) -> bool {
        self.opt_level == "0" && self.debug_assertions
    }
}

/// Panic strategy used during compilation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
pub enum PanicStrategy {
    /// `panic=unwind` — rustc's default.
    Unwind,
    /// `panic=abort`.
    Abort,
}

impl PanicStrategy {
    /// The `-C panic` value for this strategy.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Unwind => "unwind",
            Self::Abort => "abort",
        }
    }
}

impl fmt::Display for PanicStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `-C strip` level as cargo passes it to rustc.
///
/// Cargo sets `debuginfo` on its own whenever a profile turns `debug` off,
/// so this is part of the compile identity rather than a reason to exclude
/// an invocation.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum StripLevel {
    /// `strip=none` — rustc's default.
    #[default]
    None,
    /// `strip=debuginfo`.
    Debuginfo,
    /// `strip=symbols`.
    Symbols,
}

impl StripLevel {
    /// The `-C strip` value for this level.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Debuginfo => "debuginfo",
            Self::Symbols => "symbols",
        }
    }

    /// Whether this is rustc's default level, omitted from canonical JSON.
    #[must_use]
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

impl fmt::Display for StripLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod profile_divergence_tests {
    use super::{PanicStrategy, Profile, StripLevel};

    fn dev() -> Profile {
        Profile {
            opt_level: "0".to_owned(),
            debuginfo: 2,
            debug_assertions: true,
            overflow_checks: true,
            panic: PanicStrategy::Unwind,
            strip: StripLevel::None,
        }
    }

    #[test]
    fn equal_profiles_do_not_diverge() {
        assert_eq!(dev().divergence(&dev()), None);
    }

    #[test]
    fn only_the_diverging_fields_are_named() {
        let requested = Profile {
            debuginfo: 1,
            ..dev()
        };
        assert_eq!(
            dev().divergence(&requested),
            Some(("debuginfo=2".to_owned(), "debuginfo=1".to_owned()))
        );
    }

    #[test]
    fn several_diverging_fields_stay_in_parallel() {
        let requested = Profile {
            opt_level: "3".to_owned(),
            debuginfo: 0,
            ..dev()
        };
        assert_eq!(
            dev().divergence(&requested),
            Some((
                "opt-level=0, debuginfo=2".to_owned(),
                "opt-level=3, debuginfo=0".to_owned()
            ))
        );
    }
}
