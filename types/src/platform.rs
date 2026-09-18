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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
}

impl Profile {
    /// Returns true if this is a debug profile (`opt_level` "0" with `debug_assertions`).
    #[must_use]
    pub fn is_debug(&self) -> bool {
        self.opt_level == "0" && self.debug_assertions
    }
}

/// Panic strategy used during compilation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
