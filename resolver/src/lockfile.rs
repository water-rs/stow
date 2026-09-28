//! `Cargo.lock` extraction for the dropped-lockfile semantics.
//!
//! The published `cargo` keeps its `TomlLockfile → Resolve` decoder
//! (`ops::lockfile`) private, so the two pieces a dropped lockfile
//! contributes — registry pins (admission into the yanked whitelist) and
//! git pins (locked to their sha via `PackageRegistry::register_lock`) —
//! are read straight out of `cargo_util_schemas::lockfile::TomlLockfile`.
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

/// Every sourced `[[package]]` entry in `contents` — the set the yanked
/// whitelist admits.
pub fn lockfile_package_ids(contents: &str) -> CargoResult<BTreeSet<PackageId>> {
    let lock: TomlLockfile = toml::from_str(contents)?;
    let mut ids = BTreeSet::new();
    for package in lock.package.iter().flatten() {
        if let Some(id) = package_id(&package.name, &package.version, package.source.as_ref())? {
            ids.insert(id);
        }
    }
    Ok(ids)
}

/// For each git-sourced `[[package]]`, the ids of its git-sourced
/// dependencies — the `(package, deps)` pairs `register_lock` consumes
/// verbatim. A dep entry that omits `version` (unambiguous in the
/// lockfile) resolves its version from the sibling `[[package]]` of the
/// same name and source, as `ops::lockfile` does when joining
/// dependencies back to nodes.
pub fn lockfile_git_pins(contents: &str) -> CargoResult<Vec<(PackageId, Vec<PackageId>)>> {
    let lock: TomlLockfile = toml::from_str(contents)?;
    let packages: Vec<_> = lock.package.iter().flatten().collect();
    let mut out = Vec::new();
    for package in &packages {
        let Some(node) = package_id(&package.name, &package.version, package.source.as_ref())?
        else {
            continue;
        };
        if !node.source_id().is_git() {
            continue;
        }
        let mut deps = Vec::new();
        for dep in package.dependencies.iter().flatten() {
            let version = match dep.version.as_deref() {
                Some(v) => v.to_string(),
                // `name (source)` entries name a sibling exactly; the
                // ambiguity case the version elides for cannot be a git
                // dep here without a source.
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
        out.push((node, deps));
    }
    Ok(out)
}
