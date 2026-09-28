//! Fetch a resolve input into a real directory on disk.
//!
//! The `.crate` tarball lane (`resolve_crate` parity — the bundled
//! `Cargo.lock` stays in place) and the git lane (a tree fetched
//! without cloning history at any https git host,
//! `resolve_github_project` generalized per #417). Everything lands
//! under a caller-owned directory; the resolve reads the tree with
//! cargo's own manifest/config walk.

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
        .timeout(std::time::Duration::from_secs(120))
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
    Ok(dir.to_path_buf())
}

/// Pick the root manifest of a materialized tree.
///
/// `select_manifest` parity: the shallowest `Cargo.lock` whose
/// directory also carries a `Cargo.toml` roots the workspace it pins;
/// absent any lockfile the tree's own shallowest `Cargo.toml` does.
/// When `drop_lockfile`, every `Cargo.lock` under the workspace root is
/// deleted and the root one's contents returned for the resolve's
/// whitelist/git-pin handling.
///
/// # Errors
/// No manifest found, or filesystem failures.
///
/// # Panics
/// A manifest path's parent always exists — the walk only yields
/// children of `root`.
pub fn prepare_project_tree(root: &Path, drop_lockfile: bool) -> CargoResult<Materialized> {
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
    let mut manifest_path = None;
    for dir in &lock_dirs {
        if let Some((_, manifest)) = manifest_dirs.iter().find(|(dir2, _)| dir2 == dir) {
            manifest_path = Some(manifest.clone());
            break;
        }
    }
    if manifest_path.is_none() {
        manifest_path = manifest_dirs.first().map(|(_, manifest)| manifest.clone());
    }
    let manifest_path =
        manifest_path.with_context(|| format!("no Cargo.toml under {}", root.display()))?;

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
        manifest_path,
        dropped_lockfile,
    })
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
