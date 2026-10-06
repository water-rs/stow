//! Pinned source trees a project's own git checkout does not carry
//! (stow#558).
//!
//! Some projects reference Rust crates outside their repository —
//! Bun's root `Cargo.toml` names `vendor/lolhtml`, populated by its
//! `scripts/build/deps/lolhtml.ts` before cargo ever runs. The
//! resolver lane never executes upstream build scripts, so the
//! operator pins those inputs instead: a `--source-trees` file
//! declares the exact project commit and, per project, the exact
//! commit of each extra repository and the destination it lands at.
//!
//! Nothing here guesses: a preparation applies only to the project it
//! declares, the lane fetches the project at its declared commit, and
//! every destination must be missing or empty inside the fetched tree
//! — a declared path that already holds content fails the resolve
//! rather than silently shadowing what the repository ships.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use cargo::CargoResult;
use tracing::debug;

/// Worker threads materializing one project's declared sources —
/// synchronous `git` runs on scoped resolver threads; the lane's
/// project pool of 4 bounds source fetches at 16 in flight.
const SOURCE_TREE_WORKERS: usize = 4;

/// An exact git commit id, parsed by `gix-hash`'s own `ObjectId` —
/// the sha1 object ids native git serves; nothing is hand-rolled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCommit(gix_hash::ObjectId);

impl GitCommit {
    /// Parse a full sha1 hex commit id — the object ids native git
    /// serves.
    ///
    /// # Errors
    /// `raw` is not a complete object id in a hash git understands.
    pub fn parse(raw: &str) -> CargoResult<Self> {
        let id = gix_hash::ObjectId::from_hex(raw.as_bytes())
            .with_context(|| format!("`{raw}` is not a full git commit id"))?;
        Ok(Self(id))
    }

    /// The commit's canonical hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.to_string()
    }
}

/// A project-relative path a prepared source lands at.
///
/// Portable forward-slash components only — no absolute, drive,
/// `..`, `.`, backslash, or `.git` component may name a destination,
/// so a declaration can never escape the project scratch or shadow
/// the checkout's own metadata.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RelativeSourcePath(String);

impl RelativeSourcePath {
    /// Validate `raw` as a safe project-relative destination.
    ///
    /// # Errors
    /// `raw` is empty or carries a non-normal component — traversal,
    /// absolute/drive-qualified, backslash, or a git-metadata alias.
    pub fn parse(raw: &str) -> CargoResult<Self> {
        let reject =
            |why: &str| anyhow::anyhow!("source destination `{raw}` is not allowed: {why}");
        if raw.is_empty() {
            return Err(reject("empty path"));
        }
        if raw.contains('\\') {
            return Err(reject("backslash separators"));
        }
        if raw.starts_with('/') || raw.contains(':') {
            return Err(reject("absolute or drive-qualified path"));
        }
        for component in raw.split('/') {
            if component.is_empty() {
                return Err(reject("empty component"));
            }
            if component == "." || component == ".." {
                return Err(reject("`..` or `.` component"));
            }
            // Git metadata names are never legal destinations, in
            // whichever spelling a platform would resolve them —
            // case-insensitive `.git`, the NTFS 8.3 aliases `git~1`/
            // `git~2`, and trailing-dot/space trimmings.
            let trimmed = component.trim_end_matches(['.', ' ']);
            if trimmed.eq_ignore_ascii_case(".git")
                || trimmed.eq_ignore_ascii_case("git~1")
                || trimmed.eq_ignore_ascii_case("git~2")
            {
                return Err(reject("git metadata component"));
            }
        }
        Ok(Self(raw.to_owned()))
    }

    /// The path as declared, forward-slash separated.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One extra source tree a project needs inside its checkout: the
/// repository, the exact commit to fetch, and the project-relative
/// destination it materializes at.
///
/// The source host must serve fetches by the raw commit id
/// (`uploadpack.allowReachableSHA1InWant`/`allowAnySHA1InWant`, or a
/// `file://` remote) — a host that only serves named refs has no
/// fallback.
#[derive(Debug)]
pub struct PreparedSourceTree {
    destination: RelativeSourcePath,
    repo: url::Url,
    commit: GitCommit,
}

impl PreparedSourceTree {
    /// One declared source tree.
    ///
    /// # Errors
    /// `repo` is not a git-compatible absolute URL.
    pub fn new(
        destination: RelativeSourcePath,
        repo: url::Url,
        commit: GitCommit,
    ) -> CargoResult<Self> {
        if repo.cannot_be_a_base() {
            anyhow::bail!(
                "source repo `{}` is not a fetchable absolute URL",
                repo.as_str()
            );
        }
        Ok(Self {
            destination,
            repo,
            commit,
        })
    }

    /// Where inside the project this tree lands.
    #[must_use]
    pub const fn destination(&self) -> &RelativeSourcePath {
        &self.destination
    }
    /// The repository to fetch.
    #[must_use]
    pub const fn repo(&self) -> &url::Url {
        &self.repo
    }
    /// The exact commit the checkout must hold.
    #[must_use]
    pub const fn commit(&self) -> &GitCommit {
        &self.commit
    }
}

/// One project's pinned preparation: the commit its own checkout must
/// be at, plus the extra source trees the resolve materializes under
/// it first.
#[derive(Debug)]
pub struct SourcePreparation {
    commit: GitCommit,
    sources: Vec<PreparedSourceTree>,
}

impl SourcePreparation {
    /// A preparation for one project. `sources` must be nonempty (a
    /// project with nothing to fetch needs no declaration) and no two
    /// destinations may overlap — `a/b` inside declared `a` shadows
    /// content `a` already writes, so it is rejected outright.
    ///
    /// # Errors
    /// Empty source set or overlapping destinations.
    pub fn new(commit: GitCommit, sources: Vec<PreparedSourceTree>) -> CargoResult<Self> {
        if sources.is_empty() {
            anyhow::bail!("a declared project needs at least one source tree");
        }
        let mut destinations: BTreeSet<&RelativeSourcePath> = BTreeSet::new();
        for source in &sources {
            if !destinations.insert(source.destination()) {
                anyhow::bail!(
                    "source destination `{}` is declared twice",
                    source.destination().as_str()
                );
            }
        }
        for (i, outer) in sources.iter().enumerate() {
            for inner in sources.iter().skip(i + 1) {
                let a = outer.destination().as_str();
                let b = inner.destination().as_str();
                if a.starts_with(&format!("{b}/")) || b.starts_with(&format!("{a}/")) {
                    anyhow::bail!(
                        "source destinations `{a}` and `{b}` overlap — one shadows the other's tree"
                    );
                }
            }
        }
        Ok(Self { commit, sources })
    }

    /// The commit the project checkout must already sit at.
    #[must_use]
    pub const fn commit(&self) -> &GitCommit {
        &self.commit
    }
    /// The declared source trees.
    #[must_use]
    pub fn sources(&self) -> &[PreparedSourceTree] {
        &self.sources
    }
}

/// The git ref a project lane fetches for a repository.
///
/// The declared commit when the project has a preparation — the
/// repository's HEAD may have moved past the declaration (stow#573) —
/// else `HEAD`, the remote's default branch.
#[must_use]
pub fn project_fetch_ref(preparation: Option<&SourcePreparation>) -> String {
    preparation.map_or_else(|| "HEAD".to_owned(), |p| p.commit().to_hex())
}

/// `git -C <dir> rev-parse HEAD`, trimmed.
fn rev_parse_head(dir: &Path) -> CargoResult<String> {
    let output = std::process::Command::new("git")
        .current_dir(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .context("git rev-parse HEAD")?;
    if !output.status.success() {
        anyhow::bail!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Verify the project checkout sits at the declared commit.
///
/// Runs after [`crate::fetch::fetch_git`], before any source
/// acquisition or cargo work — the lane fetches the declared commit
/// itself ([`project_fetch_ref`]), and this proves the checkout
/// landed there rather than on a different tree.
///
/// # Errors
/// The checkout's `HEAD` is not the declared commit.
pub fn verify_project_commit(root: &Path, preparation: &SourcePreparation) -> CargoResult<()> {
    let head = rev_parse_head(root)?;
    let expected = preparation.commit().to_hex();
    if head != expected {
        anyhow::bail!(
            "project checkout is at {head} but the source-trees declaration pins {expected} — \
             refresh the declaration for the new commit"
        );
    }
    Ok(())
}

/// Create and prove one source's destination, returning its
/// canonical path.
///
/// Every existing ancestor and the destination itself is inspected
/// with `symlink_metadata`: a symlink anywhere on the path — inside
/// the root or pointing out of it — is rejected outright rather than
/// reasoned about, and a fetched tree or gitlink that already holds
/// content is never overwritten. The canonical path of the created
/// directory is what later containment and alias checks use — on a
/// case-insensitive filesystem `vendor/A` and `vendor/a` canonicalize
/// to the same directory, while a case-sensitive host keeps them
/// legitimately distinct.
fn establish_destination(
    canonical_root: &Path,
    root: &Path,
    source: &PreparedSourceTree,
) -> CargoResult<PathBuf> {
    let rel = source.destination().as_str();
    let mut path = root.to_path_buf();
    let components: Vec<&str> = rel.split('/').collect();
    // Everything below the first missing component cannot exist
    // either — once a gap is found, deeper segments need no lookup.
    let mut missing = false;
    for (index, component) in components.iter().enumerate() {
        path.push(component);
        if missing {
            continue;
        }
        let last = index + 1 == components.len();
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                anyhow::bail!(
                    "source destination `{rel}` crosses a symlink at `{}` — \
                     declared destinations never follow links",
                    path.display()
                );
            }
            Ok(meta) if !last => {
                if !meta.is_dir() {
                    anyhow::bail!("source destination `{rel}` crosses a non-directory");
                }
            }
            Ok(meta) => {
                // The destination itself exists: only an empty
                // directory may be claimed.
                let empty_dir = meta.is_dir()
                    && std::fs::read_dir(&path).is_ok_and(|mut entries| entries.next().is_none());
                if !empty_dir {
                    anyhow::bail!(
                        "source destination `{rel}` already holds a file tree or gitlink — \
                         the project ships its own content there"
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing = true;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspect source destination `{rel}`"));
            }
        }
    }
    if missing {
        std::fs::create_dir_all(&path)
            .with_context(|| format!("create source destination `{rel}`"))?;
    }
    let canonical = path
        .canonicalize()
        .with_context(|| format!("canonicalize source destination `{rel}`"))?;
    if !canonical.starts_with(canonical_root) {
        anyhow::bail!("source destination `{rel}` escapes the project tree");
    }
    Ok(canonical)
}

/// Create every declared destination, sequentially and before any
/// fetch runs, and prove their canonical identities are pairwise
/// disjoint — `alias/a` and `real/a` where `alias` symlinks `real`
/// (rejected above), or `vendor/A` and `vendor/a` on a
/// case-insensitive volume, must never race the source-fetch
/// fan-out.
fn establish_destinations(
    root: &Path,
    sources: &[PreparedSourceTree],
) -> CargoResult<Vec<PathBuf>> {
    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("canonicalize project root {}", root.display()))?;
    let mut destinations: Vec<PathBuf> = Vec::with_capacity(sources.len());
    for source in sources {
        let canonical = establish_destination(&canonical_root, root, source)?;
        for existing in &destinations {
            if canonical == *existing
                || canonical.starts_with(existing)
                || existing.starts_with(&canonical)
            {
                anyhow::bail!(
                    "source destinations `{}` and `{}` resolve to overlapping directories",
                    source.destination().as_str(),
                    existing.display()
                );
            }
        }
        destinations.push(canonical);
    }
    Ok(destinations)
}

/// Fetch one declared source into its already-established
/// destination and prove the checkout's `HEAD` is the declared
/// commit.
fn materialize_source(dest: &Path, source: &PreparedSourceTree) -> CargoResult<()> {
    let rel = source.destination().as_str();
    crate::fetch::fetch_git(source.repo().as_str(), &source.commit().to_hex(), dest)?;
    let head = rev_parse_head(dest)?;
    let expected = source.commit().to_hex();
    if head != expected {
        anyhow::bail!("source `{rel}` fetched {head} but the declaration pins {expected}");
    }
    debug!(%rel, %expected, "source tree materialized");
    Ok(())
}

/// Materialize every declared source tree inside the fetched root.
///
/// All destinations are created and proven canonically disjoint
/// first — a conflicting declaration never gets half-fetched — then
/// independent fetches fan out across at most
/// [`SOURCE_TREE_WORKERS`] scoped threads, all joined before the
/// first error surfaces. A project with a single source takes the
/// direct path.
///
/// # Errors
/// Destination containment/occupancy or a source fetch/commit check
/// fails.
pub fn prepare_source_trees(root: &Path, preparation: &SourcePreparation) -> CargoResult<()> {
    let sources = preparation.sources();
    let destinations = establish_destinations(root, sources)?;
    if sources.len() == 1 {
        return materialize_source(&destinations[0], &sources[0]);
    }
    let workers = sources.len().min(SOURCE_TREE_WORKERS);
    let chunk = sources.len().div_ceil(workers);
    let jobs: Vec<(&PreparedSourceTree, &PathBuf)> = sources.iter().zip(&destinations).collect();
    std::thread::scope(|scope| {
        let handles: Vec<_> = jobs
            .chunks(chunk)
            .map(|batch| {
                scope.spawn(move || {
                    for (source, dest) in batch {
                        materialize_source(dest, source)?;
                    }
                    Ok::<(), anyhow::Error>(())
                })
            })
            .collect();
        let mut first_error: Option<anyhow::Error> = None;
        for handle in handles {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
        first_error.map_or_else(|| Ok(()), Err)
    })
}
