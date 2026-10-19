//! Environment-variable name matching the way the host platform does.
//!
//! Windows treats environment names case-insensitively: the process block
//! stores `Path` and answers `PATH`, `Path` and `path` alike. Every other
//! supported platform compares names byte-exactly. Code that enumerates
//! `std::env::vars_os` and matches names against an allowlist or a prefix
//! must compare the way the OS does, or it misses variables the platform
//! itself would have matched — the Windows `Path` a case-sensitive
//! `== "PATH"` never sees.

use std::ffi::OsStr;

/// Whether `name` equals `expected` under the host's environment-name
/// rules: ASCII-case-insensitive on Windows, byte-exact elsewhere.
pub fn eq(name: impl AsRef<OsStr>, expected: impl AsRef<OsStr>) -> bool {
    let name = name.as_ref().as_encoded_bytes();
    let expected = expected.as_ref().as_encoded_bytes();
    if cfg!(windows) {
        name.eq_ignore_ascii_case(expected)
    } else {
        name == expected
    }
}

/// Whether `name` equals one of `expected`, under the host's
/// environment-name rules.
pub fn eq_any(name: impl AsRef<OsStr>, expected: &[&str]) -> bool {
    let name = name.as_ref();
    expected.iter().any(|entry| eq(name, entry))
}

/// The `expected` entry `name` equals, under the host's rules — the
/// list's own spelling, so a caller keying a map or digest on the match
/// stores one spelling however the host spelled the variable.
pub fn matching<'a>(name: impl AsRef<OsStr>, expected: &'a [&'a str]) -> Option<&'a str> {
    let name = name.as_ref();
    expected.iter().copied().find(|entry| eq(name, entry))
}

/// Whether `name` begins with `prefix`, under the host's rules.
pub fn starts_with(name: impl AsRef<OsStr>, prefix: impl AsRef<OsStr>) -> bool {
    let name = name.as_ref().as_encoded_bytes();
    let prefix = prefix.as_ref().as_encoded_bytes();
    if cfg!(windows) {
        name.len() >= prefix.len() && name[..prefix.len()].eq_ignore_ascii_case(prefix)
    } else {
        name.starts_with(prefix)
    }
}

/// Whether `name` begins with one of `prefixes`, under the host's rules.
pub fn starts_with_any(name: impl AsRef<OsStr>, prefixes: &[&str]) -> bool {
    let name = name.as_ref();
    prefixes.iter().any(|prefix| starts_with(name, prefix))
}

/// Whether `name` ends with `suffix`, under the host's rules.
pub fn ends_with(name: impl AsRef<OsStr>, suffix: impl AsRef<OsStr>) -> bool {
    let name = name.as_ref().as_encoded_bytes();
    let suffix = suffix.as_ref().as_encoded_bytes();
    if cfg!(windows) {
        name.len() >= suffix.len() && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    } else {
        name.ends_with(suffix)
    }
}

/// `name` without `prefix`, under the host's rules — `None` when `name`
/// does not begin with it. Callers' prefixes are ASCII, so a match always
/// splits on a UTF-8 boundary; `get` keeps even a non-ASCII one safe.
#[must_use]
pub fn strip_prefix<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    if starts_with(name, prefix) {
        name.get(prefix.len()..)
    } else {
        None
    }
}

/// The spelling a pattern-matched name is keyed under when no list entry
/// carries the canonical form.
///
/// ASCII-uppercase on Windows, the `CARGO_*` family's own convention, so
/// `cargo_target_…` and `CARGO_TARGET_…` key identically. Elsewhere
/// matching was byte-exact and the name already is its own spelling —
/// and distinct-case variables are distinct variables, so folding them
/// would be wrong.
#[must_use]
pub fn canonical(name: &str) -> String {
    if cfg!(windows) {
        name.to_ascii_uppercase()
    } else {
        name.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality_matches_under_host_rules() {
        assert!(eq("PATH", "PATH"));
        assert!(!eq("PATH", "PATHEXT"));
        #[cfg(windows)]
        {
            assert!(eq("Path", "PATH"));
            assert!(eq("path", "PATH"));
        }
        #[cfg(not(windows))]
        assert!(!eq("Path", "PATH"));
    }

    #[test]
    fn prefixes_match_under_host_rules() {
        assert!(starts_with("CARGO_TARGET_X_LINKER", "CARGO_TARGET_"));
        assert!(!starts_with("CARGO", "CARGO_TARGET_"));
        #[cfg(windows)]
        assert!(starts_with("cargo_target_x_linker", "CARGO_TARGET_"));
        #[cfg(not(windows))]
        assert!(!starts_with("cargo_target_x_linker", "CARGO_TARGET_"));
    }

    #[test]
    fn suffixes_match_under_host_rules() {
        assert!(ends_with("CARGO_TARGET_X_LINKER", "_LINKER"));
        assert!(!ends_with("CARGO_TARGET_DIR", "_LINKER"));
        #[cfg(windows)]
        assert!(ends_with("cargo_target_x_linker", "_LINKER"));
        #[cfg(not(windows))]
        assert!(!ends_with("cargo_target_x_linker", "_LINKER"));
    }

    #[test]
    fn list_matches_return_the_lists_spelling() {
        const VARS: &[&str] = &["PATH", "VCToolsInstallDir"];
        assert_eq!(matching("PATH", VARS), Some("PATH"));
        assert_eq!(matching("HOME", VARS), None);
        #[cfg(windows)]
        {
            assert_eq!(matching("Path", VARS), Some("PATH"));
            assert_eq!(
                matching("vctoolsinstalldir", VARS),
                Some("VCToolsInstallDir")
            );
        }
        #[cfg(not(windows))]
        {
            assert_eq!(matching("Path", VARS), None);
            assert_eq!(matching("vctoolsinstalldir", VARS), None);
        }
    }

    #[test]
    fn any_of_variants_cover_the_whole_list() {
        const VARS: &[&str] = &["CC", "CXX"];
        const PREFIXES: &[&str] = &["CC_", "CXX_"];
        assert!(eq_any("CXX", VARS));
        assert!(!eq_any("LD", VARS));
        assert!(starts_with_any("CFLAGS_TARGET", &["CFLAGS_", "LDFLAGS_"]));
        assert_eq!(starts_with_any("cc_target", PREFIXES), cfg!(windows));
    }

    #[test]
    fn strip_prefix_returns_the_remainder() {
        assert_eq!(
            strip_prefix("CARGO_UNSTABLE_X", "CARGO_UNSTABLE_"),
            Some("X")
        );
        assert_eq!(strip_prefix("CARGO_HOME", "CARGO_UNSTABLE_"), None);
        #[cfg(windows)]
        assert_eq!(
            strip_prefix("cargo_unstable_x", "CARGO_UNSTABLE_"),
            Some("x")
        );
        #[cfg(not(windows))]
        assert_eq!(strip_prefix("cargo_unstable_x", "CARGO_UNSTABLE_"), None);
    }

    #[test]
    fn canonical_folds_only_where_names_fold() {
        #[cfg(windows)]
        assert_eq!(canonical("cargo_target_x_linker"), "CARGO_TARGET_X_LINKER");
        #[cfg(not(windows))]
        assert_eq!(canonical("cargo_target_x_linker"), "cargo_target_x_linker");
    }
}
