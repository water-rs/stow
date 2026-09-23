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
//!    commit, streamed through [`crate::util::tarball::collect_tar_gz`] into
//!    `git_checkouts_path()`. A tarball is unpacked the way a checkout
//!    behaves: symlinks materialize their target's contents (a flat VFS has
//!    no link primitive), and files the resolver never reads keep their
//!    paths with empty contents so target autodiscovery still sees them.
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
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context as _;
use url::Url;

use crate::core::global_cache_tracker;
use crate::core::{Dependency, GitReference, Package, PackageId, SourceId};
use crate::sources::source::{MaybePackage, QueryKind, Source};
use crate::sources::{IndexSummary, RecursivePathSource};
use crate::util::CargoResult;
use crate::util::context::GlobalContext;
use crate::util::fs;
use crate::util::hex::short_hash;
use crate::util::interning::InternedString;
use crate::util::tarball::{self, TarPrefix};

thread_local! {
    /// Checkout paths a codeload fetch is already writing, with the
    /// waiters to wake when the fetcher finishes or its future drops.
    /// The resolver freshens distinct source instances concurrently and
    /// several `SourceId`s can name the same repo at the same commit —
    /// without a shared gate every concurrent fetcher sees the checkout
    /// absent, re-downloads the tarball, and the loser's rename collides
    /// with the winner's tree.
    static CHECKOUT_FETCHES: RefCell<HashMap<PathBuf, Vec<futures::channel::oneshot::Sender<()>>>> =
        RefCell::new(HashMap::new());
}

/// Ownership of one in-flight checkout fetch. Releasing it wakes every
/// `Source` instance that waited on the same checkout path.
struct CheckoutFetch {
    key: PathBuf,
}

impl CheckoutFetch {
    /// `Owner` when this caller runs the fetch; `Wait` when another
    /// source instance is already fetching this checkout path.
    fn acquire(key: &Path) -> CheckoutFetchClaim {
        CHECKOUT_FETCHES.with(
            |fetches| match fetches.borrow_mut().entry(key.to_path_buf()) {
                Entry::Vacant(slot) => {
                    slot.insert(Vec::new());
                    CheckoutFetchClaim::Owner(CheckoutFetch {
                        key: key.to_path_buf(),
                    })
                }
                Entry::Occupied(mut slot) => {
                    let (sender, waiter) = futures::channel::oneshot::channel();
                    slot.get_mut().push(sender);
                    CheckoutFetchClaim::Wait(waiter)
                }
            },
        )
    }
}

impl Drop for CheckoutFetch {
    fn drop(&mut self) {
        CHECKOUT_FETCHES.with(|fetches| {
            if let Some(waiters) = fetches.borrow_mut().remove(&self.key) {
                for waiter in waiters {
                    let _ = waiter.send(());
                }
            }
        });
    }
}

enum CheckoutFetchClaim {
    Owner(CheckoutFetch),
    Wait(futures::channel::oneshot::Receiver<()>),
}

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

    /// `GET` a URL as a streaming body — the tarball lane, where the
    /// response may far exceed the isolate's memory. Returns the body and
    /// the Content-Length when the server sent one (the decompression
    /// bound's compression-ratio input).
    async fn get_stream(
        &self,
        url: &str,
        what: &str,
    ) -> CargoResult<(crate::util::network::http_async::BodyStream, Option<u64>)> {
        let request = http::Request::get(url).body(Vec::new())?;
        let response = self
            .gctx
            .http_async()?
            .request_stream(request)
            .await
            .with_context(|| format!("download of {what} failed"))?;
        let (parts, body) = response.into_parts();
        match parts.status {
            http::StatusCode::OK => {
                let len = parts
                    .headers
                    .get(http::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok());
                Ok((body, len))
            }
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
            // Another source instance may already hold the fetch for this
            // checkout — wait for it, then re-check the gate.
            loop {
                match CheckoutFetch::acquire(&checkout_path) {
                    CheckoutFetchClaim::Wait(waiter) => {
                        let _ = waiter.await;
                        if fs::exists(&checkout_path) {
                            break;
                        }
                        // The owner failed — try to become the next owner.
                    }
                    CheckoutFetchClaim::Owner(_fetch) => {
                        let url = format!(
                            "https://codeload.github.com/{}/{}/tar.gz/{sha}",
                            self.repo.owner, self.repo.repo
                        );
                        let (body, len) = self
                            .get_stream(&url, &format!("git tarball of `{}`", self.repo.display))
                            .await?;
                        let files = tarball::collect_tar_gz(
                            body,
                            TarPrefix::Required(PathBuf::from(&prefix)),
                            tarball::unpack_size_bound(len),
                            tarball::MAX_RESOLVE_TREE_BYTES,
                        )
                        .await?;
                        // The tree lands beside the checkout and renames
                        // into place — a failed unpack must not leave a
                        // half-tree the `fs::exists` gate would later
                        // accept as complete.
                        let staging = parent.join(format!("{prefix}.tmp"));
                        let write = async {
                            for (rel, data) in &files {
                                fs::write(staging.join(rel), data)?;
                            }
                            fs::rename(&staging, &checkout_path)
                        };
                        if let Err(e) = write.await {
                            let _ = fs::remove_dir_all(&staging);
                            return Err(e.into());
                        }
                        break;
                    }
                }
            }
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

    /// Two source instances claiming the same checkout path must not both
    /// fetch: the second waits on the first, and the wait resolves when
    /// the owner releases the fetch — including the owner's future being
    /// dropped mid-download, which used to collide on the destination
    /// rename (`Directory not empty`) or stall entirely.
    #[test]
    fn checkout_fetch_gate_serializes_instances() {
        let key = PathBuf::from("/checkout/notify-abc");
        let CheckoutFetchClaim::Owner(owner) = CheckoutFetch::acquire(&key) else {
            panic!("first acquire owns the fetch")
        };
        let CheckoutFetchClaim::Wait(waiter) = CheckoutFetch::acquire(&key) else {
            panic!("second acquire waits")
        };
        assert!(!CHECKOUT_FETCHES.with(|f| f.borrow().is_empty()));
        drop(owner);
        // The dropped owner wakes the waiter — a cancelled fetch can't
        // strand a same-checkout source behind it forever.
        futures::executor::block_on(waiter).expect("waiter woke on owner drop");
        // And a fresh acquire is the owner again.
        assert!(matches!(
            CheckoutFetch::acquire(&key),
            CheckoutFetchClaim::Owner(_)
        ));
    }
}
