//! Stow-side source (not carried from cargo): a `git` dependency hosted on
//! github.com resolved without libgit2 or a `git` binary.
//!
//! cargo's `GitSource` fetches through libgit2's smart-HTTP transport and
//! checks the commit out of a local clone. Neither exists on
//! wasm32-unknown-unknown, so this source reproduces the two observable
//! steps over plain HTTPS:
//!
//! 1. ref resolution — `GET {repo}/info/refs?service=git-upload-pack`, the
//!    same ls-remote advertisement git itself fetches, so `rev`, `branch`,
//!    `tag` and default-branch deps land on the same commit cargo would
//!    pick;
//! 2. tree materialization — `GET https://codeload.github.com/{o}/{r}/
//!    tar.gz/{sha}`, whose archive is exactly the tracked tree at that
//!    commit, unpacked through cargo's own `unpack_prefixed` (zip-bomb and
//!    overwrite protections included) into `git_checkouts_path()`.
//!
//! The result feeds the same `RecursivePathSource` cargo wraps a git
//! checkout in, so query/download/fingerprint semantics are unchanged.
//! Every platform resolves github.com deps through this source so the
//! worker and the differential harness share one path.
//!
//! Known divergence from `GitSource`: submodules are not fetched — a
//! tarball carries no gitlink commit to resolve them from, so a package
//! that only exists inside a submodule resolves as "no matching package",
//! the same error cargo reports for a package the repo does not contain.

use std::cell::RefCell;
use std::path::Path;

use anyhow::Context as _;
use url::Url;

use crate::core::global_cache_tracker;
use crate::core::{Dependency, GitReference, Package, PackageId, SourceId};
use crate::sources::source::{MaybePackage, QueryKind, Source};
use crate::sources::{IndexSummary, RecursivePathSource, registry::unpack_prefixed};
use crate::util::CargoResult;
use crate::util::context::GlobalContext;
use crate::util::fs;
use crate::util::hex::short_hash;
use crate::util::interning::InternedString;

/// The git reference a manifest asked for, before ls-remote resolves it.
#[derive(Debug, Clone)]
enum RequestedRev {
    /// A concrete commit — `?rev=<sha>` or the `#precise` lock fragment.
    Sha(String),
    /// A named reference to resolve.
    Reference(GitReference),
}

/// GitHub owner/repo pair parsed out of a `SourceId` URL.
#[derive(Debug, Clone)]
struct GitHubRepo {
    owner: String,
    repo: String,
    /// URL as the dependency declared it, for error messages.
    display: String,
}

/// `Some` for `github.com/owner/repo` URLs (any scheme), `None` otherwise.
fn github_repo(url: &Url) -> Option<GitHubRepo> {
    match url.host_str() {
        Some("github.com") | Some("www.github.com") => {}
        _ => return None,
    }
    let mut segments = url.path_segments()?.filter(|s| !s.is_empty());
    let owner = segments.next()?;
    let repo = segments.next()?;
    if segments.next().is_some() {
        return None;
    }
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some(GitHubRepo {
        owner: owner.to_owned(),
        repo: repo.to_owned(),
        display: url.to_string(),
    })
}

/// A git [`Source`] backed by GitHub's smart-HTTP ls-remote plus a codeload
/// tarball fetch, checked out through the ambient VFS — the wasm32 port of
/// `GitSource`, and the implementation every platform uses for github.com
/// deps so the worker and the differential harness share one path.
pub struct CodeloadGitSource<'gctx> {
    repo: GitHubRepo,
    requested: RefCell<RequestedRev>,
    source_id: RefCell<SourceId>,
    path_source: RefCell<Option<RecursivePathSource<'gctx>>>,
    short_id: RefCell<Option<InternedString>>,
    /// The source identifier for Cargo's git checkout cache directories.
    ident: InternedString,
    gctx: &'gctx GlobalContext,
    quiet: bool,
}

impl<'gctx> CodeloadGitSource<'gctx> {
    /// `Some` when `source_id` is a github.com git source, `None` for git
    /// remotes hosted anywhere else (the caller bails on wasm32 or falls
    /// back to libgit2's `GitSource` on hosts).
    pub fn for_github(
        source_id: SourceId,
        gctx: &'gctx GlobalContext,
    ) -> CargoResult<Option<CodeloadGitSource<'gctx>>> {
        let Some(repo) = github_repo(source_id.url()) else {
            return Ok(None);
        };
        assert!(source_id.is_git(), "id is not git, id={}", source_id);

        let requested = source_id
            .precise_git_fragment()
            .map(|s| RequestedRev::Sha(s.to_owned()))
            .unwrap_or_else(|| RequestedRev::Reference(source_id.git_reference().unwrap().clone()));

        Ok(Some(CodeloadGitSource {
            repo,
            requested: RefCell::new(requested),
            source_id: RefCell::new(source_id),
            path_source: RefCell::new(None),
            short_id: RefCell::new(None),
            ident: ident_shallow(&source_id).into(),
            gctx,
            quiet: false,
        }))
    }

    fn mark_used(&self) -> CargoResult<()> {
        self.gctx
            .deferred_global_last_use()?
            .mark_git_checkout_used(global_cache_tracker::GitCheckout {
                encoded_git_name: self.ident,
                short_name: self.short_id.borrow().expect("update before download"),
                size: None,
            });
        Ok(())
    }

    /// `GET` a URL, erroring on non-200 with the name of what was fetched.
    async fn get(&self, url: &str, what: &str) -> CargoResult<Vec<u8>> {
        let request = http::Request::get(url).body(Vec::new())?;
        let response = self
            .gctx
            .http_async()?
            .request(request)
            .await
            .with_context(|| format!("download of {what} failed"))?;
        let (parts, body) = response.into_parts();
        match parts.status {
            http::StatusCode::OK => Ok(body),
            status => {
                anyhow::bail!("failed to get {what} from `{url}`: unexpected HTTP status {status}")
            }
        }
    }

    /// ls-remote over smart-HTTP: the same ref advertisement git fetches.
    async fn ls_remote(&self, reference: &GitReference) -> CargoResult<String> {
        let url = format!(
            "https://github.com/{}/{}/info/refs?service=git-upload-pack",
            self.repo.owner, self.repo.repo
        );
        let body = self
            .get(&url, &format!("git refs of `{}`", self.repo.display))
            .await?;
        let text = String::from_utf8(body).context("invalid UTF-8 in git ls-remote response")?;
        let refs = parse_ls_remote(&text);
        pick_ref(&refs, reference).with_context(|| {
            format!(
                "failed to find {} in git repository `{}`",
                describe_reference(reference),
                self.repo.display
            )
        })
    }

    /// The commit the requested revision names, resolving named refs over
    /// ls-remote the way git does.
    async fn resolve_sha(&self) -> CargoResult<String> {
        match &*self.requested.borrow() {
            RequestedRev::Sha(sha) => Ok(sha.clone()),
            RequestedRev::Reference(reference) => match reference {
                GitReference::Rev(rev) if is_full_sha(rev) => Ok(rev.clone()),
                reference => self.ls_remote(reference).await,
            },
        }
    }

    /// Fetch the commit's codeload tarball and check it out into
    /// `git_checkouts_path()`, mirroring `GitSource::update`'s result: a
    /// `RecursivePathSource` over the tree with a precise `source_id`.
    async fn update(&self) -> CargoResult<()> {
        if self.path_source.borrow().is_some() {
            return self.mark_used();
        }

        let sha = self.resolve_sha().await?;
        if !self.quiet {
            self.gctx
                .shell()
                .status("Updating", format!("git `{}`", self.repo.display))?;
        }

        let prefix = format!("{}-{}", self.repo.repo, sha);
        let parent = self
            .gctx
            .git_checkouts_path()
            .join(&self.ident)
            .into_path_unlocked();
        let checkout_path = parent.join(&prefix);

        if !fs::exists(&checkout_path) {
            let url = format!(
                "https://codeload.github.com/{}/{}/tar.gz/{sha}",
                self.repo.owner, self.repo.repo
            );
            let bytes = self
                .get(&url, &format!("git tarball of `{}`", self.repo.display))
                .await?;
            let temp = parent.join(format!("{prefix}.tar.gz"));
            fs::write(&temp, &bytes)?;
            let mut tarball = fs::open(&temp)?;
            unpack_prefixed(
                self.gctx,
                &mut tarball,
                Path::new(&prefix),
                &parent,
                &|_| true,
            )?;
            let _ = fs::remove_file(&temp);
        }

        let source_id = self.source_id.borrow().with_git_precise(Some(sha.clone()));
        let path_source = RecursivePathSource::new(&checkout_path, source_id, self.gctx);
        path_source.load()?;

        self.path_source.replace(Some(path_source));
        self.short_id.replace(Some(short_sha(&sha).into()));
        self.requested.replace(RequestedRev::Sha(sha));
        self.mark_used()
    }
}

#[async_trait::async_trait(?Send)]
impl<'gctx> Source for CodeloadGitSource<'gctx> {
    fn source_id(&self) -> SourceId {
        *self.source_id.borrow()
    }

    fn supports_checksums(&self) -> bool {
        false
    }

    fn requires_precise(&self) -> bool {
        true
    }

    async fn query(
        &self,
        dep: &Dependency,
        kind: QueryKind,
        f: &mut dyn FnMut(IndexSummary),
    ) -> CargoResult<()> {
        if self.path_source.borrow().is_none() {
            self.update().await?;
        }
        let src = self.path_source.borrow();
        let src = src.as_ref().unwrap();
        src.query(dep, kind, f).await
    }

    async fn download(&self, id: PackageId) -> CargoResult<MaybePackage> {
        self.mark_used()?;
        self.path_source
            .borrow_mut()
            .as_mut()
            .expect("BUG: `update()` must be called before `get()`")
            .download(id)
            .await
    }

    async fn finish_download(&self, _id: PackageId, _data: Vec<u8>) -> CargoResult<Package> {
        panic!("no download should have started")
    }

    fn fingerprint(&self, _pkg: &Package) -> CargoResult<String> {
        match &*self.requested.borrow() {
            RequestedRev::Sha(sha) => Ok(sha.clone()),
            _ => unreachable!("sha must be resolved when computing fingerprint"),
        }
    }

    fn describe(&self) -> String {
        format!("Git repository {}", self.source_id.borrow())
    }

    fn invalidate_cache(&self) {}

    fn set_quiet(&mut self, quiet: bool) {
        self.quiet = quiet;
    }
}

/// True when `s` is a full 40-hex commit sha.
fn is_full_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Display form of a [`GitReference`] for error messages.
fn describe_reference(reference: &GitReference) -> String {
    match reference {
        GitReference::DefaultBranch => "the default branch".to_owned(),
        GitReference::Branch(b) => format!("branch `{b}`"),
        GitReference::Tag(t) => format!("tag `{t}`"),
        GitReference::Rev(r) => format!("rev `{r}`"),
    }
}

/// The checkout's display short id — git's default abbreviation.
fn short_sha(sha: &str) -> String {
    sha[..sha.len().min(7)].to_owned()
}

/// `ident`/`ident_shallow` carried from `git/source.rs` (cargo 0.99.0,
/// verbatim): the libgit2 `source` module is host-only while this source
/// runs on wasm32, and checkouts keep cargo's `repo-<hash>` naming either
/// way.
fn ident(id: &SourceId) -> String {
    let ident = id
        .canonical_url()
        .raw_canonicalized_url()
        .path_segments()
        .and_then(|s| s.rev().next())
        .unwrap_or("");

    let ident = if ident.is_empty() { "_empty" } else { ident };

    format!("{}-{}", ident, short_hash(id.canonical_url()))
}

/// [`ident`] without the shallow suffix — codeload always fetches a full
/// tarball.
fn ident_shallow(id: &SourceId) -> String {
    ident(id)
}

/// Parse an `info/refs?service=git-upload-pack` response (pkt-line framed)
/// into `(sha, refname)` pairs.
fn parse_ls_remote(text: &str) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    for line in text.lines() {
        let payload = match line
            .get(..4)
            .and_then(|len| u32::from_str_radix(len, 16).ok())
        {
            Some(len) if (len as usize) <= line.len() && len >= 4 => &line[4..len as usize],
            _ => continue,
        };
        let payload = payload.split('\0').next().unwrap_or(payload);
        let mut parts = payload.splitn(2, ' ');
        let (Some(sha), Some(name)) = (parts.next(), parts.next()) else {
            continue;
        };
        if name == "HEAD" || name.starts_with("refs/") {
            refs.push((sha.to_owned(), name.to_owned()));
        }
    }
    refs
}

/// Pick the sha a [`GitReference`] names out of ls-remote output. Annotated
/// tags are peeled to the commit (`refs/tags/t^{}`) first, as git's
/// checkout does.
fn pick_ref(refs: &[(String, String)], reference: &GitReference) -> CargoResult<String> {
    let find = |name: &str| {
        refs.iter()
            .find(|(_, r)| r == name)
            .map(|(sha, _)| sha.clone())
    };
    let sha = match reference {
        GitReference::DefaultBranch => find("HEAD"),
        GitReference::Branch(branch) => find(&format!("refs/heads/{branch}")),
        GitReference::Tag(tag) => {
            find(&format!("refs/tags/{tag}^{{}}")).or_else(|| find(&format!("refs/tags/{tag}")))
        }
        GitReference::Rev(rev) => find(&format!("refs/heads/{rev}"))
            .or_else(|| find(&format!("refs/tags/{rev}^{{}}")))
            .or_else(|| find(&format!("refs/tags/{rev}")))
            .or_else(|| {
                if rev.starts_with("refs/") {
                    find(rev)
                } else {
                    find(&format!("refs/{rev}"))
                }
            }),
    };
    sha.ok_or_else(|| anyhow::format_err!("reference {} not found", describe_reference(reference)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every URL form cargo accepts for a GitHub dep parses into
    /// owner/repo; a non-GitHub host parses to `None`, which
    /// [`SourceId::load`] on wasm turns into an error naming the host.
    #[test]
    fn github_repo_parses_every_form() {
        for (url, expected) in [
            (
                "https://github.com/serde-rs/json",
                Some(("serde-rs", "json")),
            ),
            (
                "https://github.com/serde-rs/json.git",
                Some(("serde-rs", "json")),
            ),
            (
                "ssh://git@github.com/serde-rs/json.git",
                Some(("serde-rs", "json")),
            ),
            (
                "https://github.com/serde-rs/json/",
                Some(("serde-rs", "json")),
            ),
            ("https://gitlab.com/serde-rs/json", None),
            ("https://github.com/serde-rs", None),
            ("https://github.com/serde-rs/json/tree/main", None),
        ] {
            let url = Url::parse(url).unwrap();
            assert_eq!(
                github_repo(&url).map(|r| (r.owner, r.repo)),
                expected.map(|(o, r)| (o.to_string(), r.to_string())),
                "{url}"
            );
        }
    }
}
