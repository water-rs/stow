//! Fetch a resolve input into a real directory on disk.
//!
//! The `.crate` tarball lane (`resolve_crate` parity) and the git lane
//! (a tree fetched without cloning history at any https git host,
//! `resolve_github_project` generalized per #417). Everything lands
//! under a caller-owned directory; the resolve reads the tree with
//! cargo's own manifest/config walk.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use cargo::CargoResult;
use flate2::read::GzDecoder;
use tar::Archive;
use tracing::{debug, info};

/// A project tree materialized on disk, plus the dropped-lockfile data
/// the resolve consumes.
#[derive(Debug)]
pub struct Materialized {
    /// Root manifest the resolve reads (the tree's own `Cargo.toml` —
    /// the one `select_manifest` would root the workspace at).
    pub manifest_path: PathBuf,
    /// The root `Cargo.lock`'s contents when the lane dropped it —
    /// yanked admission + git pins for [`select_ws_with_opts`].
    ///
    /// [`select_ws_with_opts`]: crate::select::select_ws_with_opts
    pub dropped_lockfile: Option<String>,
}

/// Where a `.crate` download lives on crates.io's static host.
#[must_use]
pub fn crate_tarball_url(crate_name: &str, version: &semver::Version) -> String {
    format!("https://static.crates.io/crates/{crate_name}/{crate_name}-{version}.crate")
}

/// Download and unpack one published `.crate` under `dir`, returning
/// the unpacked package directory (the tarball's single top-level
/// `name-version/` entry).
///
/// # Errors
/// Network, tarball, or filesystem failures.
pub async fn fetch_crate(
    crate_name: &str,
    version: &semver::Version,
    dir: &Path,
) -> CargoResult<PathBuf> {
    use zenwave::Client as _;

    let url = crate_tarball_url(crate_name, version);
    let mut client = zenwave::client()
        .timeout(std::time::Duration::from_mins(2))
        .follow_redirect();
    let response = client
        .get(&url)
        .map_err(|error| anyhow::anyhow!("crate download request: {error}"))?
        .await
        .map_err(|error| anyhow::anyhow!("download {url}: {error}"))?;
    let bytes = response
        .into_body()
        .into_bytes()
        .await
        .map_err(|error| anyhow::anyhow!("read {url} body: {error}"))?;

    let root = dir.join(format!("{crate_name}-{version}"));
    let decoder = GzDecoder::new(bytes.as_ref());
    let mut archive = Archive::new(decoder);
    for entry in archive.entries().context("iterate crate tarball")? {
        let mut entry = entry.context("crate tarball entry")?;
        let path = entry.path().context("crate tarball entry path")?;
        // Strip the single top-level `name-version` component.
        let mut components = path.components();
        components.next();
        let rel: PathBuf = components.as_path().to_path_buf();
        if rel.as_os_str().is_empty() {
            continue;
        }
        let dest = root.join(&rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
        entry
            .unpack(&dest)
            .with_context(|| format!("unpack {}", dest.display()))?;
    }
    Ok(root)
}

/// Fetch a git repository's tree at `git_ref` into `dir`.
///
/// No history clone — a depth-1 fetch of the ref (or the remote's HEAD
/// when `git_ref` is `"HEAD"`). Any https host, via the system `git` —
/// codeload parity, plus hosts codeload doesn't serve (#417).
///
/// Synchronous, like the rest of the resolve path: callers running
/// under a runtime wrap it in `spawn_blocking` (or run it on the
/// resolver's own threads).
///
/// # Errors
/// Git or filesystem failures.
pub fn fetch_git(url: &str, git_ref: &str, dir: &Path) -> CargoResult<PathBuf> {
    let run = |args: &[&str]| -> CargoResult<std::process::Output> {
        let output = std::process::Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .with_context(|| format!("git {}", args[0]))?;
        if !output.status.success() {
            anyhow::bail!(
                "git {} failed: {}",
                args[0],
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(output)
    };

    run(&["init"])?;
    run(&["remote", "add", "origin", url])?;

    // `HEAD` resolves to the remote's default branch; anything else is
    // fetched as named.
    let fetch_ref = if git_ref == "HEAD" {
        let output = run(&["ls-remote", "--symref", "origin", "HEAD"])?;
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| {
                line.strip_prefix("ref: ")
                    .and_then(|rest| rest.strip_suffix("\tHEAD"))
            })
            .unwrap_or("HEAD")
            .to_owned()
    } else {
        git_ref.to_owned()
    };
    debug!(%url, %fetch_ref, "resolve fetch");
    run(&["fetch", "--depth", "1", "origin", &fetch_ref])?;
    run(&["checkout", "--detach", "FETCH_HEAD"])?;
    // A fetched tree's gitlinks are empty dirs until materialized —
    // resolve the pinned tree's own `.gitmodules` at the recorded
    // submodule commits (never `--remote`), depth-1 like the parent
    // fetch. Without it a workspace member or `path` dep living in a
    // submodule reads as a missing manifest (stow#543).
    run(&[
        "submodule",
        "update",
        "--init",
        "--recursive",
        "--depth",
        "1",
    ])?;
    Ok(dir.to_path_buf())
}

/// Pick the root manifest of a materialized tree — selection only.
///
/// A caller runs it on the project's own checkout *before* any
/// supplemental source lands (stow#558): an imported tree carrying a
/// `Cargo.toml`+`Cargo.lock` pair can never outrank the manifest the
/// project itself selects.
///
/// `select_manifest` parity: the shallowest `Cargo.lock` whose
/// directory also carries a `Cargo.toml` roots the workspace it pins;
/// absent any lockfile the tree's own shallowest `Cargo.toml` does.
///
/// # Errors
/// No manifest found, or filesystem failures.
pub fn select_manifest(root: &Path) -> CargoResult<PathBuf> {
    // `select_manifest` parity: the shallowest `Cargo.lock` whose
    // directory also carries `Cargo.toml` roots the workspace it pins —
    // else the shallowest `Cargo.toml` at all. Lock dirs sort
    // shallowest-first, lexicographic within a depth.
    let files = walk(root);
    let mut manifest_dirs: Vec<(PathBuf, PathBuf)> = files
        .iter()
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml"))
        .filter_map(|path| path.parent().map(|dir| (dir.to_path_buf(), path.clone())))
        .collect();
    manifest_dirs.sort_by(|a, b| {
        a.0.components()
            .count()
            .cmp(&b.0.components().count())
            .then_with(|| a.0.cmp(&b.0))
    });
    let mut lock_dirs: Vec<PathBuf> = files
        .iter()
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some("Cargo.lock"))
        .filter_map(|path| path.parent().map(Path::to_path_buf))
        .collect();
    lock_dirs.sort_by(|a, b| {
        a.components()
            .count()
            .cmp(&b.components().count())
            .then_with(|| a.cmp(b))
    });
    for dir in &lock_dirs {
        if let Some((_, manifest)) = manifest_dirs.iter().find(|(dir2, _)| dir2 == dir) {
            return Ok(manifest.clone());
        }
    }
    manifest_dirs
        .first()
        .map(|(_, manifest)| manifest.clone())
        .with_context(|| format!("no Cargo.toml under {}", root.display()))
}

/// The post-selection half of tree preparation.
///
/// The lockfile semantics of the selected manifest's workspace root:
/// when `drop_lockfile`, every `Cargo.lock` under the workspace root —
/// including any a prepared source just brought in — is deleted and
/// the root one's contents returned for the resolve's
/// whitelist/git-pin handling.
///
/// # Errors
/// Filesystem failures.
///
/// # Panics
/// A manifest path's parent always exists — selection only yields
/// children of the walked root.
pub fn prepare_selected_manifest(
    manifest_path: &Path,
    drop_lockfile: bool,
) -> CargoResult<Materialized> {
    let ws_root = manifest_path
        .parent()
        .expect("manifest path has a parent")
        .to_path_buf();

    let mut dropped_lockfile = None;
    if drop_lockfile {
        let root_lock = ws_root.join("Cargo.lock");
        if root_lock.exists() {
            dropped_lockfile =
                Some(std::fs::read_to_string(&root_lock).context("read dropped Cargo.lock")?);
        }
        for entry in walk(&ws_root) {
            if entry.file_name().and_then(|name| name.to_str()) == Some("Cargo.lock") {
                std::fs::remove_file(&entry)
                    .with_context(|| format!("drop {}", entry.display()))?;
            }
        }
        info!(
            ?ws_root,
            dropped = dropped_lockfile.is_some(),
            "lockfile dropped"
        );
    }

    Ok(Materialized {
        manifest_path: manifest_path.to_path_buf(),
        dropped_lockfile,
    })
}

/// Pick the root manifest of a materialized tree and apply its
/// workspace's lockfile handling — [`select_manifest`] then
/// [`prepare_selected_manifest`], for callers whose tree needs no
/// supplemental sources.
///
/// # Errors
/// No manifest found, or filesystem failures.
pub fn prepare_project_tree(root: &Path, drop_lockfile: bool) -> CargoResult<Materialized> {
    let manifest_path = select_manifest(root)?;
    prepare_selected_manifest(&manifest_path, drop_lockfile)
}

/// Remove every dev-dependency table from each `Cargo.toml` under
/// `root` — `[dev-dependencies]`, the legacy `dev_dependencies`
/// spelling, and both spellings inside every `[target.<cfg>]` table.
///
/// The fetched-crate lanes call this before resolving: a consumer that
/// depends on the published crate never resolves those tables — the
/// registry's dependency metadata does not carry them, and `cargo
/// install` resolves the package's own manifest with them pruned
/// (`require_optional_deps` off). Left in place they resolve anyway,
/// since the unpacked package is the workspace root and a member's
/// dev-dependencies join its resolve: a dev-dependency whose
/// requirement cannot resolve (a yanked-only release) fails a lane no
/// consumer would ever fail, and a resolvable one's requirement still
/// unifies with the normal dependencies, pinning shared nodes below
/// the version a consumer computes. The project's own lanes —
/// `resolve_git`, `resolve_project_dir` — keep theirs: a project's
/// own lockfile legitimately includes its dev-dependencies.
///
/// A `[features]` entry may still name a dev-dependency through
/// `dep/feature` or `dep?/feature` — hashbrown 0.15.5's
/// `nightly = ["bumpalo/allocator_api"]` names a dev-only `bumpalo`.
/// The manifest is legal, and for a consumer the entry is inert —
/// cargo resolves a dependency's features without its
/// dev-dependencies — but with the table removed the same entry fails
/// manifest validation outright. The strip therefore also removes
/// every feature entry naming a key only a removed dev table declared
/// (stow#831); a feature left empty stays defined, since a consumer
/// may still request it.
///
/// The edit is structural (`toml_edit`), and a manifest carrying no
/// dev-dependency table is never rewritten — a caller's tree without
/// them survives byte-for-byte.
///
/// # Errors
/// A manifest that fails to parse, or filesystem failures.
pub fn strip_dev_dependencies(root: &Path) -> CargoResult<()> {
    for path in walk(root) {
        if path.file_name().and_then(|name| name.to_str()) != Some("Cargo.toml") {
            continue;
        }
        let source =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let mut document = source
            .parse::<toml_edit::DocumentMut>()
            .with_context(|| format!("parse {}", path.display()))?;
        if strip_dev_tables(&mut document) {
            std::fs::write(&path, document.to_string())
                .with_context(|| format!("write {}", path.display()))?;
        }
    }
    Ok(())
}

/// `strip_dev_dependencies`' single-document half; returns whether the
/// document changed — a removed dev table, or a `[features]` entry
/// purged for naming a key only a removed table declared (a feature
/// edit alone still requires the manifest's rewrite).
fn strip_dev_tables(document: &mut toml_edit::DocumentMut) -> bool {
    let root = document.as_table_mut();
    // What a `name/feature` entry names is the dependency's table key —
    // never its `package =` rename target.
    let mut removed_keys = BTreeSet::new();
    let mut changed = strip_dev_keys(root, &mut removed_keys);
    if let Some(targets) = root
        .get_mut("target")
        .and_then(toml_edit::Item::as_table_like_mut)
    {
        for (_cfg, target) in targets.iter_mut() {
            let Some(target) = target.as_table_like_mut() else {
                continue;
            };
            changed |= strip_dev_keys(target, &mut removed_keys);
        }
    }
    if removed_keys.is_empty() {
        return changed;
    }

    // A removed key that a surviving normal or build table also
    // declares — at the root or under any target — stays a valid
    // feature target (a crate may be both kinds of dependency).
    let mut remaining_keys = BTreeSet::new();
    let mut collect_keys = |table: &dyn toml_edit::TableLike| {
        for name in ["dependencies", "build-dependencies", "build_dependencies"] {
            if let Some(deps) = table.get(name).and_then(toml_edit::Item::as_table_like) {
                remaining_keys.extend(deps.iter().map(|(key, _)| key.to_owned()));
            }
        }
    };
    collect_keys(root);
    if let Some(targets) = root.get("target").and_then(toml_edit::Item::as_table_like) {
        for (_cfg, target) in targets.iter() {
            if let Some(target) = target.as_table_like() {
                collect_keys(target);
            }
        }
    }

    let Some(features) = root
        .get_mut("features")
        .and_then(toml_edit::Item::as_table_like_mut)
    else {
        return changed;
    };
    for (_feature, item) in features.iter_mut() {
        let Some(entries) = item.as_array_mut() else {
            continue;
        };
        // `dep/feature` and `dep?/feature` name a dependency — the
        // only entries the purge touches. A `dep:name` entry cannot
        // name a dev-dependency and a bare word is a feature, and a
        // feature whose array empties stays defined for the consumers
        // requesting it.
        let mut index = 0;
        while index < entries.len() {
            let purge = entries
                .get(index)
                .and_then(toml_edit::Value::as_str)
                .is_some_and(|entry| {
                    let Some((name, _)) = entry.split_once('/') else {
                        return false;
                    };
                    let name = name.strip_suffix('?').unwrap_or(name);
                    removed_keys.contains(name) && !remaining_keys.contains(name)
                });
            if purge {
                entries.remove(index);
                changed = true;
            } else {
                index += 1;
            }
        }
    }
    changed
}

/// Remove `table`'s dev-dependency tables (`dev-dependencies` and the
/// legacy `dev_dependencies`), collecting their dependency keys into
/// `removed_keys`; returns whether any table was removed.
fn strip_dev_keys(
    table: &mut dyn toml_edit::TableLike,
    removed_keys: &mut BTreeSet<String>,
) -> bool {
    let mut removed = false;
    for name in ["dev-dependencies", "dev_dependencies"] {
        let Some(item) = table.remove(name) else {
            continue;
        };
        removed = true;
        if let Some(deps) = item.as_table_like() {
            removed_keys.extend(deps.iter().map(|(key, _)| key.to_owned()));
        }
    }
    removed
}

/// Files (not directories) under `root`, shallowest first. The `.git`
/// dir of a fetched checkout is skipped — a resolve never reads it.
fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                if path.file_name().is_some_and(|name| name == ".git") {
                    continue;
                }
                stack.push(path);
            } else if meta.is_file() {
                out.push(path);
            }
        }
    }
    out.sort_by_key(|path| path.components().count());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// stow#831: `dep/feature` and `dep?/feature` entries naming a
    /// removed dev-dependency key — root or target-gated — are purged;
    /// entries whose name a surviving table still declares, `dep:`
    /// entries, and bare feature names are untouched, and a feature
    /// whose array empties stays defined.
    #[test]
    fn the_strip_purges_only_entries_naming_removed_dev_keys() {
        let mut document = r#"
[dependencies]
dep = "1"
shared = "1"

[dev-dependencies]
devdep = "1"
shared = "1"

[target.'cfg(unix)'.dev-dependencies]
cfgdev = "1"

[features]
nightly = ["devdep/x", "dep/x", "plain", "dep:dep"]
weak = ["devdep?/x"]
target = ["cfgdev/f", "other"]
both = ["shared/s", "devdep/z"]
emptied = ["devdep/y"]
"#
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
        assert!(strip_dev_tables(&mut document));

        assert!(document.get("dev-dependencies").is_none());
        assert!(
            document["target"]["cfg(unix)"]
                .as_table_like()
                .unwrap()
                .get("dev-dependencies")
                .is_none()
        );
        assert!(
            document["dependencies"]
                .as_table_like()
                .unwrap()
                .get("dep")
                .is_some(),
            "the normal dependency table survives"
        );

        let entries = |name: &str| -> Vec<String> {
            document["features"][name]
                .as_array()
                .unwrap_or_else(|| panic!("`{name}` stays a defined feature"))
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(entries("nightly"), ["dep/x", "plain", "dep:dep"]);
        assert_eq!(entries("weak"), Vec::<String>::new());
        assert_eq!(entries("target"), ["other"]);
        assert_eq!(entries("both"), ["shared/s"]);
        assert_eq!(entries("emptied"), Vec::<String>::new());
    }

    /// A manifest without dev-dependency tables reports unchanged —
    /// the caller never rewrites it.
    #[test]
    fn the_strip_reports_unchanged_without_dev_tables() {
        let mut document = r#"
[dependencies]
dep = "1"

[features]
f = ["dep/x"]
"#
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
        let before = document.to_string();
        assert!(!strip_dev_tables(&mut document));
        assert_eq!(document.to_string(), before);
    }
}
