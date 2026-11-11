//! The cache policy of one build: which crates the graph analysis found
//! worth a public lookup.
//!
//! The set lives in the memory of the process that decides the build's
//! units. The analysis commits to it while cargo builds, and the plan path
//! reads the latest set on every plan, so an entry that lands mid-build
//! gates the unit it names from the commit onward (stow#347).

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::rustc_args::ParsedRustcArgs;

/// One crate the analysis marked as cached for one target.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CachePolicyEntry {
    pub target: String,
    pub crate_name: String,
}

/// The committed entries as `(target, normalized crate name)` pairs.
#[derive(Debug, Default, Clone)]
struct AllowEntries(BTreeSet<(String, String)>);

/// The build's allow set as the plan path reads it: the latest commit.
///
/// Cheap pre-identity gate: with a policy present, only crates the graph
/// analysis marked as cached are worth the identity computation + network
/// round trip. Keyed by canonical crate name — the only identity component
/// that is free to read from the rustc args and stable across cargo's
/// ephemeral metadata. A stale allow (name cached, variant missing) costs
/// one 404; a deny costs nothing.
#[derive(Debug, Clone)]
pub struct AllowSet(tokio::sync::watch::Receiver<Arc<AllowEntries>>);

/// The side of the allow set that commits entries.
#[derive(Debug)]
pub struct AllowWriter(tokio::sync::watch::Sender<Arc<AllowEntries>>);

/// A build's allow set seeded with `entries`, and the writer that adds to
/// it.
#[must_use]
pub fn allow_cell(entries: &[CachePolicyEntry]) -> (AllowWriter, AllowSet) {
    let writer = AllowWriter(tokio::sync::watch::channel(Arc::default()).0);
    writer.commit(entries);
    let set = AllowSet(writer.0.subscribe());
    (writer, set)
}

impl AllowWriter {
    /// Add `entries` to the set: every plan after this reads them.
    pub fn commit(&self, entries: &[CachePolicyEntry]) {
        self.0.send_modify(|allowed| {
            Arc::make_mut(allowed).0.extend(entries.iter().map(|entry| {
                (
                    entry.target.clone(),
                    normalized_crate_name(&entry.crate_name),
                )
            }));
        });
    }
}

impl AllowEntries {
    fn contains(&self, target: &str, crate_name: &str) -> bool {
        self.0
            .contains(&(target.to_owned(), normalized_crate_name(crate_name)))
    }
}

fn normalized_crate_name(crate_name: &str) -> String {
    crate_name.replace('-', "_")
}

/// Whether the policy permits a public lookup for this invocation.
///
/// `None` means "no policy configured" and the caller treats it as
/// allowed. `fallback_target` covers an invocation that does not spell
/// `--target`: the consumer target the driver resolved for this build.
pub fn public_cache_allowed(
    allowed: Option<&AllowSet>,
    parsed: &ParsedRustcArgs,
    fallback_target: Option<&str>,
) -> Option<bool> {
    let allowed = allowed?;
    let target = parsed
        .target
        .clone()
        .or_else(|| fallback_target.map(str::to_owned))
        .filter(|target| !target.trim().is_empty())?;

    // The driver's entries name packages; `parsed.crate_name` is the lib
    // name `[lib] name` may have renamed (stow#578), so the package name
    // comes from the registry source path. An invocation without one is
    // a non-registry unit, which can hold no entry: the same answer a
    // missing entry gives. This signature has no error channel — its
    // caller's decision type has none — so a probe error is logged and
    // treated as deny, not silently allowed.
    let crate_name = match stow_types::public_cache::detect_registry_crate_version(parsed) {
        Ok(Some((name, _version))) => name,
        Ok(None) => return Some(false),
        Err(error) => {
            tracing::warn!(
                crate_name = %parsed.crate_name,
                %error,
                "registry identity probe failed; treating invocation as not allowed"
            );
            return Some(false);
        }
    };
    Some(allowed.0.borrow().contains(&target, &crate_name))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{CachePolicyEntry, allow_cell, public_cache_allowed};

    /// stow#578: the driver names entries by package name, but the
    /// invocation spells the lib target name — a `[lib] name` rename must
    /// still find its entry through the registry source path.
    #[test]
    fn a_renamed_lib_matches_its_package_entry() {
        let parsed = stow_types::rustc::ParsedRustcArgs::parse(&[
            OsString::from("--crate-name"),
            OsString::from("debug_unreachable"),
            OsString::from("--crate-type"),
            OsString::from("lib"),
            OsString::from("--target"),
            OsString::from("x86_64-unknown-linux-gnu"),
            OsString::from(
                "/root/.cargo/registry/src/index.crates.io-0123abcd/new_debug_unreachable-1.0.6/src/lib.rs",
            ),
        ])
        .expect("parse");
        assert_eq!(parsed.crate_name, "debug_unreachable");

        let (_writer, allowed) = allow_cell(&[CachePolicyEntry {
            target: "x86_64-unknown-linux-gnu".to_owned(),
            crate_name: "new-debug-unreachable".to_owned(),
        }]);
        assert_eq!(
            public_cache_allowed(Some(&allowed), &parsed, None),
            Some(true),
            "the entry named for the package must cover the renamed lib unit"
        );
    }

    /// A unit with no registry source path is a non-registry invocation:
    /// it can hold no entry, so the answer is deny — the same as a
    /// missing entry.
    #[test]
    fn a_non_registry_unit_is_denied() {
        let (_writer, allowed) = allow_cell(&[]);
        let parsed = stow_types::rustc::ParsedRustcArgs::parse(&[
            OsString::from("--crate-name"),
            OsString::from("mycrate"),
            OsString::from("--crate-type"),
            OsString::from("lib"),
            OsString::from("--target"),
            OsString::from("x86_64-unknown-linux-gnu"),
            OsString::from("src/lib.rs"),
        ])
        .expect("parse");

        assert_eq!(
            public_cache_allowed(Some(&allowed), &parsed, None),
            Some(false),
            "a non-registry unit gets the missing-entry answer"
        );
    }

    /// An entry committed after the set was built gates the unit it names
    /// from the commit onward; no policy at all allows everything.
    #[test]
    fn a_later_commit_is_read_by_the_next_plan() {
        let parsed = stow_types::rustc::ParsedRustcArgs::parse(&[
            OsString::from("--crate-name"),
            OsString::from("serde"),
            OsString::from("--crate-type"),
            OsString::from("lib"),
            OsString::from("--target"),
            OsString::from("x86_64-unknown-linux-gnu"),
            OsString::from(
                "/h/.cargo/registry/src/index.crates.io-0123abcd/serde-1.0.219/src/lib.rs",
            ),
        ])
        .expect("parse");
        let (writer, allowed) = allow_cell(&[]);
        assert_eq!(
            public_cache_allowed(Some(&allowed), &parsed, None),
            Some(false)
        );
        writer.commit(&[CachePolicyEntry {
            target: "x86_64-unknown-linux-gnu".to_owned(),
            crate_name: "serde".to_owned(),
        }]);
        assert_eq!(
            public_cache_allowed(Some(&allowed), &parsed, None),
            Some(true)
        );
        assert_eq!(public_cache_allowed(None, &parsed, None), None);
    }
}
