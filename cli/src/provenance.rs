//! Which crates of this build were compiled locally, and what that
//! forbids.
//!
//! A cached artifact is not interchangeable with a local build of the same
//! identity. rustc stamps every crate with an SVH that follows the source
//! path, so the CI copy compiled under the runner's `CARGO_HOME` and the
//! local copy compiled under the developer's never match, and a crate
//! linked against one of them rejects the other:
//!
//! ```text
//! error[E0460]: found possibly newer version of crate `unicode_ident`
//!               which `proc_macro2` depends on
//! ```
//!
//! stow's own identity cannot see that difference — both copies carry the
//! same stable `c_metadata`, which is the point of the identity rewrite —
//! so the rule has to be about provenance instead: once a crate is built
//! locally, every artifact that was compiled against that crate must be
//! built locally too. Serving one of them from the cache turns a partial
//! cache into a failed build rather than a slower one.
//!
//! The markers live beside the cache-policy allow markers, in the
//! per-build directory the wrapper already receives through
//! `STOW_CACHE_POLICY_PATH`. Cargo runs a unit only after its
//! dependencies, so a dependency's marker is on disk before any consumer
//! asks about it. Without that directory (a bare `stow rustc` outside
//! `stow check`) there is no build to reason about and nothing is
//! recorded or refused.

use std::path::{Path, PathBuf};

use stow_types::rustc::ParsedExternCrate;

use crate::cache_policy;

/// Subdirectory of the per-build policy directory holding one marker per
/// locally compiled crate.
const LOCAL_BUILD_DIR: &str = "local-build";

/// Record that `crate_name` was compiled locally for `target` in this
/// build, so artifacts compiled against it stay off the cache.
///
/// Silently does nothing when the invocation carries no per-build policy
/// directory: there is no build-wide view to record into.
pub async fn record_local_build(target: &str, crate_name: &str) -> stow_types::error::Result<()> {
    let Some(dir) = local_build_dir(target) else {
        return Ok(());
    };
    async_fs::create_dir_all(&dir)
        .await
        .map_err(|error| stow_types::stow_error!("create {}: {error}", dir.display()))?;
    let marker = dir.join(marker_name(crate_name));
    async_fs::write(&marker, [])
        .await
        .map_err(|error| stow_types::stow_error!("write {}: {error}", marker.display()))
}

/// The first `--extern` dependency of this invocation that the build
/// already compiled locally, if any.
///
/// Its presence means no cached artifact can serve this unit: rustc links
/// a crate to the exact copy of each dependency it was compiled against,
/// and a cached artifact was compiled against the CI copy, not the one
/// cargo is about to hand this invocation.
///
/// `None` when every dependency can still come from the cache, when the
/// unit has no dependencies, and when the invocation has no per-build
/// policy directory to consult.
pub fn locally_built_dependency(
    target: &str,
    extern_crates: &[ParsedExternCrate],
) -> Option<String> {
    if extern_crates.is_empty() {
        return None;
    }
    let dir = local_build_dir(target)?;
    locally_built_dependency_in(&dir, extern_crates)
}

fn locally_built_dependency_in(dir: &Path, extern_crates: &[ParsedExternCrate]) -> Option<String> {
    extern_crates
        .iter()
        .map(|dependency| dependency.crate_name.as_str())
        .find(|crate_name| dir.join(marker_name(crate_name)).exists())
        .map(ToOwned::to_owned)
}

/// The per-build directory holding this target's local-build markers.
fn local_build_dir(target: &str) -> Option<PathBuf> {
    let policy_dir = cache_policy::policy_dir()?;
    Some(marker_dir(&policy_dir, target))
}

fn marker_dir(policy_dir: &Path, target: &str) -> PathBuf {
    policy_dir.join(LOCAL_BUILD_DIR).join(target)
}

/// Cargo crate names reach rustc in both spellings (`unicode-ident` on
/// crates.io, `unicode_ident` in `--extern`), and a dependency list may
/// disagree with the consumer's own spelling, so both map to one marker.
fn marker_name(crate_name: &str) -> String {
    crate_name.replace('-', "_")
}

#[cfg(test)]
mod tests {
    use stow_types::rustc::ParsedExternCrate;

    use super::{locally_built_dependency_in, marker_dir, marker_name};

    fn build_with_local(crates: &[&str]) -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = marker_dir(temp.path(), "aarch64-apple-darwin");
        std::fs::create_dir_all(&dir).expect("create marker dir");
        for name in crates {
            std::fs::write(dir.join(marker_name(name)), []).expect("write marker");
        }
        (temp, dir)
    }

    fn externs(names: &[&str]) -> Vec<ParsedExternCrate> {
        names
            .iter()
            .map(|name| ParsedExternCrate {
                crate_name: (*name).to_owned(),
                path: std::path::PathBuf::from(format!("deps/lib{name}-0123456789abcdef.rmeta")),
            })
            .collect()
    }

    /// crates.io spells the crate with a hyphen and `--extern` with an
    /// underscore; one crate has to mean one marker.
    #[test]
    fn hyphens_and_underscores_name_the_same_marker() {
        let (_temp, dir) = build_with_local(&["unicode-ident"]);
        assert_eq!(
            locally_built_dependency_in(&dir, &externs(&["unicode_ident"])),
            Some("unicode_ident".to_owned())
        );
    }

    /// Dependencies nobody built locally leave the cache usable.
    #[test]
    fn untouched_dependencies_leave_the_cache_usable() {
        let (_temp, dir) = build_with_local(&["memchr"]);
        assert_eq!(
            locally_built_dependency_in(&dir, &externs(&["unicode_ident", "serde"])),
            None
        );
    }

    /// One locally built dependency is enough to rule the cache out, even
    /// beside dependencies that are still cacheable.
    #[test]
    fn one_local_dependency_rules_out_the_cache() {
        let (_temp, dir) = build_with_local(&["unicode_ident"]);
        assert_eq!(
            locally_built_dependency_in(&dir, &externs(&["serde", "unicode_ident"])),
            Some("unicode_ident".to_owned())
        );
    }

    /// A leaf crate depends on nothing, so nothing can make it unusable.
    #[test]
    fn a_leaf_invocation_is_always_usable() {
        let (_temp, dir) = build_with_local(&["unicode_ident"]);
        assert_eq!(locally_built_dependency_in(&dir, &externs(&[])), None);
    }
}
