//! `Cargo.lock` extraction for the dropped-lockfile semantics.
//!
//! The published `cargo` keeps its `TomlLockfile → Resolve` decoder
//! (`ops::lockfile`) private, so the pieces a dropped lockfile
//! contributes — registry pins (admission into the yanked whitelist),
//! used git pins (locked to their sha via
//! `PackageRegistry::register_lock`), and `[[patch.unused]]` git
//! sources — are read straight out of
//! `cargo_util_schemas::lockfile::TomlLockfile` in one parse.
//!
//! Entries without a `source` are workspace members and are skipped, as
//! the vendored `lockfile_package_ids` does.

use std::collections::BTreeSet;

use cargo::CargoResult;
use cargo::core::{PackageId, SourceId};
use cargo_util_schemas::lockfile::TomlLockfile;

fn package_id(
    name: &str,
    version: &str,
    source: Option<&cargo_util_schemas::lockfile::TomlLockfileSourceId>,
) -> CargoResult<Option<PackageId>> {
    let Some(source) = source else {
        return Ok(None);
    };
    Ok(Some(PackageId::try_new(
        name,
        version,
        SourceId::from_url(source.source_str())?,
    )?))
}

/// A git source id that has not been preloaded yet, appended to `out`.
/// `SourceId` equality ignores `precise`, so when an unused patch row
/// names the same canonical source as a used `[[package]]` pin, the
/// used pin already inserted keeps its sha; a distinct ref is retained.
fn preload_git_source(id: PackageId, seen: &mut BTreeSet<SourceId>, out: &mut Vec<SourceId>) {
    if id.source_id().is_git() && seen.insert(id.source_id()) {
        out.push(id.source_id());
    }
}

/// What one dropped `Cargo.lock` contributes to a regenerate resolve —
/// parsed once, consumed whole by the `dropped_lockfile` input.
pub struct DroppedLockfile {
    /// Sourced `[[package]]` registry ids — the yanked whitelist.
    pub registry_ids: BTreeSet<PackageId>,
    /// For each git-sourced `[[package]]`, the ids of its git-sourced
    /// dependencies — the `(package, deps)` pairs `register_lock`
    /// consumes verbatim. `patch.unused` rows never register: they are
    /// not in the keep graph.
    pub git_pins: Vec<(PackageId, Vec<PackageId>)>,
    /// Precise git source ids `add_sources` preloads before patch
    /// registration — every git source a `[[package]]` pins, plus every
    /// git source a `[[patch.unused]]` row records (used-package rows
    /// first, so same-source precedence lands on the used pin's sha).
    /// Unioned for preloading only: unused patch rows admit nothing to
    /// the registry whitelist and nothing to the keep graph.
    pub git_source_ids: Vec<SourceId>,
}

impl DroppedLockfile {
    /// One `TomlLockfile` parse — every contribution a dropped lockfile
    /// makes. A malformed source fails the parse via cargo's errors;
    /// nothing is skipped or guessed.
    pub fn parse(contents: &str) -> CargoResult<Self> {
        let lock: TomlLockfile = toml::from_str(contents)?;
        let packages: Vec<_> = lock.package.iter().flatten().collect();
        let mut registry_ids = BTreeSet::new();
        let mut git_pins = Vec::new();
        let mut git_source_ids = Vec::new();
        let mut seen_sources = BTreeSet::new();
        for package in &packages {
            let Some(node) = package_id(&package.name, &package.version, package.source.as_ref())?
            else {
                continue;
            };
            if node.source_id().is_registry() {
                registry_ids.insert(node);
            }
            if !node.source_id().is_git() {
                continue;
            }
            preload_git_source(node, &mut seen_sources, &mut git_source_ids);
            let mut deps = Vec::new();
            for dep in package.dependencies.iter().flatten() {
                let version = match dep.version.as_deref() {
                    Some(v) => v.to_string(),
                    // `name (source)` entries name a sibling exactly; the
                    // ambiguity case the version elides for cannot be a
                    // git dep here without a source.
                    None => match packages
                        .iter()
                        .find(|p| {
                            p.name == dep.name
                                && p.source.as_ref().map(|s| s.source_str().as_str())
                                    == dep.source.as_ref().map(|s| s.source_str().as_str())
                        })
                        .map(|p| p.version.clone())
                    {
                        Some(v) => v,
                        None => continue,
                    },
                };
                if let Some(id) = package_id(&dep.name, &version, dep.source.as_ref())?
                    && id.source_id().is_git()
                {
                    deps.push(id);
                }
            }
            git_pins.push((node, deps));
        }
        // Unused patches still have to *load* their source at patch
        // registration — cargo proves their packages are not needed —
        // so a deleted ref's only resolvable identity is the pin the
        // lockfile recorded. Their source ids join the preload union
        // after every used-package pin; nothing else is contributed.
        for entry in &lock.patch.unused {
            if let Some(id) = package_id(&entry.name, &entry.version, entry.source.as_ref())? {
                preload_git_source(id, &mut seen_sources, &mut git_source_ids);
            }
        }
        Ok(Self {
            registry_ids,
            git_pins,
            git_source_ids,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn toml_document(value: &serde_json::Value) -> String {
        toml::to_string(value).expect("fixture TOML serializes")
    }

    /// A `[[patch.unused]]` row contributes its git source id for
    /// preloading — never a `register_lock` pair, never whitelist
    /// admission — and when it shares the used package's canonical
    /// source, the used pin's sha is the one retained.
    #[test]
    fn unused_patch_contributes_only_a_git_source_id() {
        let lock = toml_document(&json!({
            "version": 4,
            "package": [
                {
                    "name": "dep_a",
                    "version": "1.0.0",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                },
                {
                    "name": "depgit",
                    "version": "0.1.0",
                    "source": "git+https://github.com/o/dep?branch=gone#aaaabbbbccccddddeeeeffff00001111",
                },
            ],
            "patch": {
                "unused": [
                    {
                        "name": "depgit",
                        "version": "0.1.0",
                        "source": "git+https://github.com/o/dep?branch=gone#22223333444455556666777788889999",
                    },
                    {
                        "name": "other",
                        "version": "0.1.0",
                        "source": "git+https://github.com/o/dep?branch=other#ccccddddeeeeffff0000111122223333",
                    },
                ],
            },
        }));
        let dropped = DroppedLockfile::parse(&lock).unwrap();
        assert_eq!(
            dropped
                .registry_ids
                .iter()
                .map(|id| id.name().as_str())
                .collect::<Vec<_>>(),
            vec!["dep_a"],
            "only sourced [[package]] registry rows admit"
        );
        assert_eq!(
            dropped
                .git_pins
                .iter()
                .map(|(id, _)| id.name().as_str())
                .collect::<Vec<_>>(),
            vec!["depgit"],
            "unused patch rows never register a node"
        );
        let fragments: Vec<Option<&str>> = dropped
            .git_source_ids
            .iter()
            .map(|id| id.precise_git_fragment())
            .collect();
        assert_eq!(dropped.git_source_ids.len(), 2, "distinct refs retained");
        assert_eq!(
            fragments[0],
            Some("aaaabbbbccccddddeeeeffff00001111"),
            "same canonical source: the used pin's sha wins, unused is not reinserted"
        );
        assert_eq!(
            fragments[1],
            Some("ccccddddeeeeffff0000111122223333"),
            "a distinct ref keeps its own pin"
        );
    }

    /// A malformed source in any row fails the parse — no fallback.
    #[test]
    fn malformed_sources_fail_the_parse() {
        let lock = toml_document(&json!({
            "package": [
                {
                    "name": "bad",
                    "version": "1.0.0",
                    "source": "not a source",
                },
            ],
        }));
        assert!(DroppedLockfile::parse(&lock).is_err());
    }
}
