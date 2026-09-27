//! Stow-side source (not carried from cargo): a `git` dependency resolved
//! without libgit2 or a `git` binary — on github.com through the codeload
//! tarball, on every other https host through a shallow smart-HTTP fetch.
//!
//! cargo's `GitSource` fetches through libgit2's smart-HTTP transport and
//! checks the commit out of a local clone. Neither exists on
//! wasm32-unknown-unknown, so this source reproduces the two observable
//! steps over plain HTTPS:
//!
//! 1. ref resolution — `GET {repo}/info/refs?service=git-upload-pack`, the
//!    same ls-remote advertisement git itself fetches (v2 servers answer a
//!    capability list and a `command=ls-refs` POST carries the refs), so
//!    `rev`, `branch`, `tag` and default-branch deps land on the same
//!    commit cargo would pick;
//! 2. tree materialization — GitHub keeps `GET https://codeload.github.
//!    com/{o}/{r}/tar.gz/{sha}` (cheaper and cached); any other host
//!    answers `POST {repo}/git-upload-pack` with `want <sha>`, `deepen 1`
//!    and `done`, and [`super::pack::tree_files`] decodes the returned
//!    pack. Either way the tree is unpacked into `git_checkouts_path()`
//!    the way a checkout behaves: symlinks materialize their target's
//!    contents (a flat VFS has no link primitive), and files the resolver
//!    never reads keep their paths with empty contents so target
//!    autodiscovery still sees them.
//!
//! The result feeds the same `RecursivePathSource` cargo wraps a git
//! checkout in, so query/download/fingerprint semantics are unchanged.
//! Every platform resolves every git dep through this source so the
//! worker and the differential harness share one path.
//!
//! Known divergence from cargo's `GitSource`: submodules are not
//! fetched — a tarball carries no gitlink commit to resolve them from
//! and the shallow pack's gitlinks stay unfetched — so a package that
//! only exists inside a submodule resolves as "no matching package", the
//! same error cargo reports for a package the repo does not contain.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::Path;
use std::path::PathBuf;
use std::rc::{Rc, Weak};

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
    /// Checkout paths a tree fetch is already writing, with the
    /// waiters to wake when the fetcher finishes or its future drops.
    /// The resolver freshens distinct source instances concurrently and
    /// several `SourceId`s can name the same repo at the same commit —
    /// without a shared gate every concurrent fetcher sees the checkout
    /// absent, re-downloads the tarball, and the loser's rename collides
    /// with the winner's tree.
    ///
    /// Claims are keyed by the ambient VFS's pointer so dedupe stays
    /// inside one resolve: each request's checkout tree is its own
    /// [`MemoryVfs`][crate::util::fs::MemoryVfs], so a claim shared
    /// across requests could only strand a waiter on a fetcher writing
    /// a different tree — and a request the runtime abandons mid-fetch
    /// never drops its owner, which used to leak the claim and stall
    /// every later resolve behind a wake nobody sends.
    static CHECKOUT_FETCHES: RefCell<HashMap<CheckoutFetchKey, CheckoutFetchEntry>> =
        RefCell::new(HashMap::new());
}

/// The claim-map key: the checkout path inside one resolve's ambient VFS.
/// The VFS identity is its `Rc` pointer — a raw address is enough because
/// the entry holds a `Weak`, which keeps the `RcBox` (and therefore the
/// address) allocated until the claim ends without keeping the tree alive.
#[derive(PartialEq, Eq, Hash, Clone)]
struct CheckoutFetchKey {
    vfs: usize,
    path: PathBuf,
}

struct CheckoutFetchEntry {
    /// Keeps the claiming resolve's VFS allocation — but not its tree —
    /// alive so a dead claim's pointer key can never be recycled into a
    /// later resolve's VFS while the entry lives. When the resolve's
    /// last `Rc` drops, the `Weak` goes dead and the next `acquire`
    /// prunes the abandoned claim: an owner a cancelled request never
    /// drops can neither strand waiters nor pin the whole checkout tree.
    vfs: Weak<dyn fs::Vfs>,
    waiters: Vec<futures::channel::oneshot::Sender<()>>,
}

/// Ownership of one in-flight checkout fetch. Releasing it wakes every
/// `Source` instance that waited on the same checkout path.
struct CheckoutFetch {
    key: CheckoutFetchKey,
}

impl CheckoutFetch {
    /// `Owner` when this caller runs the fetch; `Wait` when another
    /// source instance of the same resolve is already fetching this
    /// checkout path.
    fn acquire(key: &Path) -> CheckoutFetchClaim {
        let vfs = fs::current();
        let claim_key = CheckoutFetchKey {
            vfs: Rc::as_ptr(&vfs).cast::<()>() as usize,
            path: key.to_path_buf(),
        };
        CHECKOUT_FETCHES.with(|fetches| {
            let mut fetches = fetches.borrow_mut();
            // A claim whose VFS is gone belongs to a resolve the runtime
            // abandoned: its owner is never dropped, so prune it here —
            // its waiters died with the same request.
            fetches.retain(|_, entry| entry.vfs.strong_count() > 0);
            match fetches.entry(claim_key.clone()) {
                Entry::Vacant(slot) => {
                    slot.insert(CheckoutFetchEntry {
                        vfs: Rc::downgrade(&vfs),
                        waiters: Vec::new(),
                    });
                    CheckoutFetchClaim::Owner(CheckoutFetch { key: claim_key })
                }
                Entry::Occupied(mut slot) => {
                    let (sender, waiter) = futures::channel::oneshot::channel();
                    slot.get_mut().waiters.push(sender);
                    CheckoutFetchClaim::Wait(waiter)
                }
            }
        })
    }
}

impl Drop for CheckoutFetch {
    fn drop(&mut self) {
        CHECKOUT_FETCHES.with(|fetches| {
            if let Some(entry) = fetches.borrow_mut().remove(&self.key) {
                for waiter in entry.waiters {
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

/// The last path segment of a repo URL minus a `.git` suffix — the name a
/// checkout directory takes.
fn repo_name(url: &Url) -> String {
    url.path_segments()
        .and_then(|mut s| s.next_back())
        .filter(|s| !s.is_empty())
        .map(|s| s.strip_suffix(".git").unwrap_or(s).to_owned())
        .unwrap_or_else(|| "repo".to_owned())
}

/// How the tree at the resolved commit is fetched for one remote.
enum Remote {
    /// github.com — the codeload tarball (cheaper and cached) plus the
    /// `/commit/{rev}.patch` header for abbreviated `rev`s.
    GitHub(GitHubRepo),
    /// Any other `http(s)` remote — shallow smart-HTTP `fetch`.
    SmartHttp {
        /// Repo URL as declared, trailing slashes trimmed — the
        /// `{url}/info/refs` and `{url}/git-upload-pack` endpoint root.
        url: String,
        /// The URL in error messages.
        display: String,
        /// Repo name for the checkout directory prefix.
        name: String,
    },
}

impl Remote {
    /// The remote in log/status/error messages.
    fn display(&self) -> &str {
        match self {
            Remote::GitHub(repo) => &repo.display,
            Remote::SmartHttp { display, .. } => display,
        }
    }

    /// Repo name for the checkout directory prefix.
    fn repo_name(&self) -> &str {
        match self {
            Remote::GitHub(repo) => &repo.repo,
            Remote::SmartHttp { name, .. } => name,
        }
    }
}

/// A git [`Source`] backed by HTTPS alone — GitHub's smart-HTTP ls-remote
/// plus codeload tarball for github.com, a shallow smart-HTTP `fetch` for
/// every other host — checked out through the ambient VFS. It is the
/// wasm32 port of cargo's libgit2 `GitSource`, and the implementation
/// every platform uses so the worker and the differential harness share
/// one path.
pub struct GitTreeSource<'gctx> {
    remote: Remote,
    requested: RefCell<RequestedRev>,
    source_id: RefCell<SourceId>,
    /// `Rc` so `query`/`download` can take the loaded source out of the
    /// cell before awaiting — a `Ref`/`RefMut` held across an `.await`
    /// deadlocks (panics on wasm) against a concurrent `update`'s
    /// `replace`.
    path_source: RefCell<Option<Rc<RecursivePathSource<'gctx>>>>,
    short_id: RefCell<Option<InternedString>>,
    /// The source identifier for Cargo's git checkout cache directories.
    ident: InternedString,
    /// The remote's `info/refs` answer once fetched — protocol version,
    /// capability set, and (v0) the ref table.
    advertisement: RefCell<Option<crate::git_proto::Advertisement>>,
    gctx: &'gctx GlobalContext,
    quiet: bool,
}

impl<'gctx> GitTreeSource<'gctx> {
    /// `Some` when `source_id` is a git remote this source can reach —
    /// github.com on any scheme, anything else only over `http(s)`.
    /// `None` leaves the caller to reject the remote.
    pub fn new(
        source_id: SourceId,
        gctx: &'gctx GlobalContext,
    ) -> CargoResult<Option<GitTreeSource<'gctx>>> {
        assert!(source_id.is_git(), "id is not git, id={}", source_id);
        let url = source_id.url();
        let remote = if let Some(repo) = github_repo(url) {
            Remote::GitHub(repo)
        } else {
            match url.scheme() {
                "http" | "https" => Remote::SmartHttp {
                    url: url.as_str().trim_end_matches('/').to_owned(),
                    display: url.to_string(),
                    name: repo_name(url),
                },
                _ => return Ok(None),
            }
        };

        let requested = source_id
            .precise_git_fragment()
            .map(|s| RequestedRev::Sha(s.to_owned()))
            .unwrap_or_else(|| RequestedRev::Reference(source_id.git_reference().unwrap().clone()));

        Ok(Some(GitTreeSource {
            remote,
            requested: RefCell::new(requested),
            source_id: RefCell::new(source_id),
            path_source: RefCell::new(None),
            short_id: RefCell::new(None),
            ident: ident_shallow(&source_id).into(),
            advertisement: RefCell::new(None),
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
    /// Transport failures retry — a dropped connection is the ordinary
    /// transient, not a reason to fail the dependency.
    async fn get(&self, url: &str, what: &str) -> CargoResult<Vec<u8>> {
        const ATTEMPTS: u32 = 4;
        let mut last = anyhow::format_err!("no attempts made");
        for attempt in 1..=ATTEMPTS {
            let request = http::Request::get(url).body(Vec::new())?;
            match self.gctx.http_async()?.request(request).await {
                Ok(response) => {
                    let (parts, body) = response.into_parts();
                    return match parts.status {
                        http::StatusCode::OK => Ok(body),
                        status => {
                            anyhow::bail!(
                                "failed to get {what} from `{url}`: unexpected HTTP status {status}"
                            )
                        }
                    };
                }
                Err(error) => {
                    last = error.context(format!("download of {what} failed"));
                    if attempt == ATTEMPTS {
                        break;
                    }
                }
            }
        }
        Err(last)
    }

    /// `GET` a URL as a streaming body — the tarball lane, where the
    /// response may far exceed the isolate's memory. Returns the body and
    /// the Content-Length when the server sent one (the decompression
    /// bound's compression-ratio input). Transport failures retry.
    async fn get_stream(
        &self,
        url: &str,
        what: &str,
    ) -> CargoResult<(crate::util::network::http_async::BodyStream, Option<u64>)> {
        const ATTEMPTS: u32 = 4;
        let mut last = anyhow::format_err!("no attempts made");
        for attempt in 1..=ATTEMPTS {
            let request = http::Request::get(url).body(Vec::new())?;
            match self.gctx.http_async()?.request_stream(request).await {
                Ok(response) => {
                    let (parts, body) = response.into_parts();
                    return match parts.status {
                        http::StatusCode::OK => {
                            let len = parts
                                .headers
                                .get(http::header::CONTENT_LENGTH)
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse().ok());
                            Ok((body, len))
                        }
                        status => anyhow::bail!(
                            "failed to get {what} from `{url}`: unexpected HTTP status {status}"
                        ),
                    };
                }
                Err(error) => {
                    last = error.context(format!("download of {what} failed"));
                    if attempt == ATTEMPTS {
                        break;
                    }
                }
            }
        }
        Err(last)
    }

    /// ls-remote over smart-HTTP on github.com: the v0 ref advertisement
    /// git fetches.
    async fn ls_remote(&self, repo: &GitHubRepo, reference: &GitReference) -> CargoResult<String> {
        let url = format!(
            "https://github.com/{}/{}/info/refs?service=git-upload-pack",
            repo.owner, repo.repo
        );
        let body = self
            .get(&url, &format!("git refs of `{}`", repo.display))
            .await?;
        let text = String::from_utf8(body).context("invalid UTF-8 in git ls-remote response")?;
        let refs = crate::git_proto::parse_ls_remote(&text);
        pick_ref(&refs, reference).with_context(|| {
            format!(
                "failed to find {} in git repository `{}`",
                describe_reference(reference),
                repo.display
            )
        })
    }

    /// The remote's `info/refs` answer, fetched once — the advertisement
    /// doubles as protocol detection and (v0) the ref table.
    async fn advertisement(&self, url: &str) -> CargoResult<crate::git_proto::Advertisement> {
        if let Some(adv) = self.advertisement.borrow().as_ref() {
            return Ok(adv.clone());
        }
        let adv = crate::git_proto::advertise(self.gctx.http_async()?, url).await?;
        *self.advertisement.borrow_mut() = Some(adv.clone());
        Ok(adv)
    }

    /// Ref resolution for a non-GitHub remote: the advertisement's refs
    /// when the server speaks v0, a `ls-refs` request when it speaks v2.
    async fn ls_remote_smart(&self, url: &str, reference: &GitReference) -> CargoResult<String> {
        let adv = self.advertisement(url).await?;
        let refs = if adv.v2 {
            crate::git_proto::ls_refs(self.gctx.http_async()?, url).await?
        } else {
            adv.refs
        };
        pick_ref(&refs, reference).with_context(|| {
            format!(
                "failed to find {} in git repository `{url}`",
                describe_reference(reference)
            )
        })
    }

    /// The commit the requested revision names, resolving named refs over
    /// ls-remote the way git does.
    async fn resolve_sha(&self) -> CargoResult<String> {
        // The resolver polls queries on one source concurrently, so no
        // borrow of `self`'s cells may live across an `.await` — copy the
        // reference out before any fetch.
        let reference = match &*self.requested.borrow() {
            RequestedRev::Sha(sha) => return Ok(sha.clone()),
            RequestedRev::Reference(reference) => reference.clone(),
        };
        match (&self.remote, &reference) {
            (Remote::GitHub(_), GitReference::Rev(rev)) if is_full_sha(rev) => Ok(rev.clone()),
            (Remote::GitHub(repo), GitReference::Rev(rev)) if looks_like_commit_hash(rev) => {
                // git's revparse resolves a `rev` against refs before
                // trying it as a commit hash — a branch or tag literally
                // named `rev` still wins. A bare hash names a commit:
                // ls-remote never carries it, so when no ref matches,
                // GitHub's commits API expands it the same way cargo's
                // `github_fast_path` does.
                match self.ls_remote(repo, &reference).await {
                    Ok(sha) => Ok(sha),
                    Err(reference_err) => self
                        .resolve_commit_sha(repo, rev)
                        .await
                        .map_err(|_| reference_err),
                }
            }
            (Remote::GitHub(repo), reference) => self.ls_remote(repo, reference).await,
            (Remote::SmartHttp { .. }, GitReference::Rev(rev)) if is_full_sha(rev) => {
                Ok(rev.clone())
            }
            (Remote::SmartHttp { url, .. }, reference) => {
                self.ls_remote_smart(url, reference).await
            }
        }
    }

    /// Expand a commit hash — short or full — to the full sha, the endpoint
    /// cargo's `github_fast_path` would query at `api.github.com`. That API
    /// is unusable from the worker: unauthenticated `api.github.com` caps at
    /// 60 requests an hour shared across every worker on the egress IP (see
    /// `crate::github_tree`). `github.com/{o}/{r}/commit/{rev}.patch` resolves
    /// an abbreviated rev server-side and answers a git format-patch header —
    /// `From <full-sha> …` — on github.com, which carries no such cap. Only
    /// the first line is read; dropping the rest of the stream lets the
    /// transport cancel it. Transport failures retry.
    async fn resolve_commit_sha(&self, repo: &GitHubRepo, rev: &str) -> CargoResult<String> {
        use futures::StreamExt as _;
        const ATTEMPTS: u32 = 4;
        let url = format!(
            "https://github.com/{}/{}/commit/{rev}.patch",
            repo.owner, repo.repo
        );
        let what = format!("commit `{rev}` of `{}`", repo.display);
        let mut last = anyhow::format_err!("no attempts made");
        for attempt in 1..=ATTEMPTS {
            let request = http::Request::get(&url).body(Vec::new())?;
            match self.gctx.http_async()?.request_stream(request).await {
                Ok(response) => {
                    let (parts, mut body) = response.into_parts();
                    return match parts.status {
                        http::StatusCode::OK => {
                            let mut buf = Vec::with_capacity(64);
                            while !buf.contains(&b'\n') && buf.len() <= 256 {
                                match body.next().await {
                                    Some(Ok(chunk)) => buf.extend_from_slice(&chunk),
                                    _ => break,
                                }
                            }
                            let line = String::from_utf8_lossy(&buf);
                            let sha = line
                                .strip_prefix("From ")
                                .and_then(|rest| rest.split_whitespace().next())
                                .unwrap_or("");
                            anyhow::ensure!(is_full_sha(sha), "unexpected `{url}` header");
                            Ok(sha.to_owned())
                        }
                        status => anyhow::bail!(
                            "failed to get {what} from `{url}`: unexpected HTTP status {status}"
                        ),
                    };
                }
                Err(error) => {
                    last = error.context(format!("download of {what} failed"));
                    if attempt == ATTEMPTS {
                        break;
                    }
                }
            }
        }
        Err(last)
    }

    /// The commit's `path → contents` map: the codeload tarball on
    /// github.com, a shallow smart-HTTP `fetch` pack everywhere else.
    async fn fetch_files(&self, sha: &str) -> CargoResult<BTreeMap<PathBuf, Vec<u8>>> {
        match &self.remote {
            Remote::GitHub(repo) => {
                let url = format!(
                    "https://codeload.github.com/{}/{}/tar.gz/{sha}",
                    repo.owner, repo.repo
                );
                let (body, len) = self
                    .get_stream(&url, &format!("git tarball of `{}`", repo.display))
                    .await?;
                // FirstComponent, not Required(prefix): codeload
                // names the top directory after the repo's
                // *current* name — a renamed repository serves
                // `new-name-<sha>/` under the old name's URL.
                tarball::collect_tar_gz(
                    body,
                    TarPrefix::FirstComponent,
                    tarball::unpack_size_bound(len),
                    tarball::MAX_RESOLVE_TREE_BYTES,
                )
                .await
            }
            Remote::SmartHttp { url, .. } => {
                let adv = self.advertisement(url).await?;
                let pack =
                    crate::git_proto::fetch_pack(self.gctx.http_async()?, url, sha, &adv).await?;
                crate::git_proto::tree_files(&pack, sha)
            }
        }
    }

    /// Fetch the commit's tree and check it out into
    /// `git_checkouts_path()`, mirroring cargo's `GitSource::update`
    /// result: a `RecursivePathSource` over the tree with a precise
    /// `source_id`.
    async fn update(&self) -> CargoResult<()> {
        if self.path_source.borrow().is_some() {
            return self.mark_used();
        }

        let sha = self.resolve_sha().await?;
        if !self.quiet {
            self.gctx
                .shell()
                .status("Updating", format!("git `{}`", self.remote.display()))?;
        }

        let prefix = format!("{}-{}", self.remote.repo_name(), sha);
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
                        let files = self.fetch_files(&sha).await?;
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

        self.path_source.replace(Some(Rc::new(path_source)));
        self.short_id.replace(Some(short_sha(&sha).into()));
        self.requested.replace(RequestedRev::Sha(sha));
        self.mark_used()
    }
}

#[async_trait::async_trait(?Send)]
impl<'gctx> Source for GitTreeSource<'gctx> {
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
        // `src.query` awaits; clone the `Rc` out so the borrow of
        // `path_source` cannot collide with a concurrent `update`'s
        // `replace`.
        let src = self
            .path_source
            .borrow()
            .clone()
            .expect("`update` leaves the path source loaded");
        src.query(dep, kind, f).await
    }

    async fn download(&self, id: PackageId) -> CargoResult<MaybePackage> {
        self.mark_used()?;
        // Same shape as `query`: downloads of several packages in one git
        // checkout run concurrently, so clone the `Rc` rather than holding
        // a borrow across the await.
        self.path_source
            .borrow()
            .clone()
            .expect("BUG: `update()` must be called before `get()`")
            .download(id)
            .await
    }

    async fn finish_download(
        &self,
        _id: PackageId,
        _body: http::Response<crate::util::network::http_async::BodyStream>,
    ) -> CargoResult<Package> {
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

/// cargo's `looks_like_commit_hash` (utils.rs): a `rev` of 7+ hex digits may
/// be an abbreviated commit — try it as one once no ref matches.
fn looks_like_commit_hash(rev: &str) -> bool {
    rev.len() >= 7 && rev.bytes().all(|b| b.is_ascii_hexdigit())
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

/// [`ident`] without the shallow suffix — checkout dirs carry no
/// shallowness marker since this source fetches no history.
fn ident_shallow(id: &SourceId) -> String {
    ident(id)
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
    use std::collections::HashMap;

    /// An [`HttpClient`] answering from an in-memory URL → response map.
    /// `ls-refs` and `fetch` are both POSTs to one `git-upload-pack`
    /// endpoint, so the map keys them apart on the request's first
    /// pkt-line command: a `"{url}#{command}"` key wins over the bare
    /// `{url}` key.
    struct MapHttp(HashMap<String, http::Response<Vec<u8>>>);

    impl crate::util::network::http_async::HttpClient for MapHttp {
        fn request<'a>(
            &'a self,
            request: http::Request<Vec<u8>>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = CargoResult<http::Response<Vec<u8>>>> + 'a>,
        > {
            let url = request.uri().to_string();
            // The body opens with a length-prefixed `command=<…>` pkt-line.
            let command = request
                .body()
                .get(4..)
                .and_then(|b| b.iter().position(|&c| c == b'\n').map(|i| &b[..i]))
                .and_then(|line| std::str::from_utf8(line).ok())
                .map(str::to_owned);
            Box::pin(async move {
                let hit = command
                    .and_then(|command| self.0.get(&format!("{url}#{command}")))
                    .or_else(|| self.0.get(&url));
                hit.cloned()
                    .ok_or_else(|| anyhow::format_err!("no recorded response for `{url}`"))
            })
        }
    }

    /// A `rev` of hex digits is a commit hash, not a ref — ls-remote never
    /// advertises it, so the `commit/{rev}.patch` header expands it to the
    /// full sha cargo would pin, the way `github_fast_path` does.
    #[test]
    fn hex_rev_expands_via_patch_header() {
        fs::set_vfs(Rc::new(crate::util::fs::MemoryVfs::new()));
        let full_sha = "cd811f7d744f65291e13131b1d907fda63ed91a1";
        let pkt = |payload: &str| format!("{:04x}{payload}", payload.len() + 4);
        let ls_remote = format!(
            "{}{}{}{}{}{}",
            pkt("# service=git-upload-pack\n"),
            "0000",
            pkt("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HEAD\0multi_ack thin-pack\n"),
            pkt("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/heads/main\n"),
            pkt("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/tags/v1.0^{}\n"),
            "0000"
        );
        let mut responses = HashMap::new();
        for (url, body) in [
            (
                "https://github.com/zed-industries/wprcontrol/info/refs?service=git-upload-pack",
                ls_remote.into_bytes(),
            ),
            (
                "https://github.com/zed-industries/wprcontrol/commit/cd811f7.patch",
                format!("From {full_sha} Mon Sep 17 00:00:00 2001\nSubject: …\n").into_bytes(),
            ),
        ] {
            responses.insert(
                url.to_string(),
                http::Response::builder().status(200).body(body).unwrap(),
            );
        }
        let mut gctx = GlobalContext::default().unwrap();
        gctx.set_http(crate::util::network::http_async::Client::new(Rc::new(
            MapHttp(responses),
        )));
        let url = Url::parse("https://github.com/zed-industries/wprcontrol").unwrap();
        let source_id = SourceId::for_git(&url, GitReference::Rev("cd811f7".to_string())).unwrap();
        let source = GitTreeSource::new(source_id, &gctx)
            .unwrap()
            .expect("github source");
        let sha = futures::executor::block_on(source.resolve_sha()).unwrap();
        assert_eq!(sha, full_sha);
        fs::replace_vfs(None);
    }

    fn pkt(payload: &[u8]) -> Vec<u8> {
        let mut out = format!("{:04x}", payload.len() + 4).into_bytes();
        out.extend_from_slice(payload);
        out
    }

    /// A non-GitHub https remote resolves a `branch` through the v2
    /// `ls-refs` exchange and materializes the fetched pack's tree into the
    /// VFS — the package then queries and downloads like any checkout.
    ///
    /// `tests/fixtures/dep.pack` is a `git pack-objects` capture of a
    /// one-commit repo holding `Cargo.toml` (name `dep`), `src/lib.rs`,
    /// `sub/file.txt`, and a `link.rs` symlink — commit `bac1a2d9…`.
    #[test]
    fn smart_http_pack_fetches_tree() {
        fs::set_vfs(Rc::new(crate::util::fs::MemoryVfs::new()));
        let pack = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/dep.pack"
        ));
        let sha = "bac1a2d9dda4a24e9b7e6e9c009fba5a94e64da6";
        let url = "https://git.example.test/dep-owner/dep-repo";

        let mut adv = pkt(b"# service=git-upload-pack\n");
        adv.extend_from_slice(b"0000");
        for line in [
            "version 2\n",
            "ls-refs\n",
            "fetch=shallow filter\n",
            "object-format=sha1\n",
        ] {
            adv.extend_from_slice(&pkt(line.as_bytes()));
        }
        adv.extend_from_slice(b"0000");

        let mut ls_refs = Vec::new();
        ls_refs.extend_from_slice(&pkt(
            format!("{sha} HEAD\nsymref-target:refs/heads/main\n").as_bytes()
        ));
        ls_refs.extend_from_slice(&pkt(format!("{sha} refs/heads/main\n").as_bytes()));
        ls_refs.extend_from_slice(b"0000");

        let mut fetch = pkt(b"packfile\n");
        let mut band = vec![1u8];
        band.extend_from_slice(pack);
        fetch.extend_from_slice(&pkt(&band));
        fetch.extend_from_slice(b"0000");

        let mut responses = HashMap::new();
        for (url, body) in [
            (format!("{url}/info/refs?service=git-upload-pack"), adv),
            (format!("{url}/git-upload-pack#command=ls-refs"), ls_refs),
            (format!("{url}/git-upload-pack#command=fetch"), fetch),
        ] {
            responses.insert(
                url,
                http::Response::builder().status(200).body(body).unwrap(),
            );
        }
        let mut gctx = GlobalContext::default().unwrap();
        gctx.set_http(crate::util::network::http_async::Client::new(Rc::new(
            MapHttp(responses),
        )));

        let repo_url = Url::parse(url).unwrap();
        let source_id =
            SourceId::for_git(&repo_url, GitReference::Branch("main".to_string())).unwrap();
        let source = GitTreeSource::new(source_id, &gctx)
            .unwrap()
            .expect("smart-http remote");
        futures::executor::block_on(source.update()).unwrap();

        let dep = Dependency::parse("dep", None, source_id).unwrap();
        let summaries =
            futures::executor::block_on(source.query_vec(&dep, QueryKind::Exact)).unwrap();
        assert_eq!(summaries.len(), 1, "expected the `dep` package");
        let package_id = match &summaries[0] {
            IndexSummary::Candidate(summary) => summary.package_id(),
            _ => panic!("expected a candidate summary"),
        };
        match futures::executor::block_on(source.download(package_id)).unwrap() {
            MaybePackage::Ready(package) => {
                let root = package.manifest_path().parent().unwrap().to_path_buf();
                // The manifest the resolver reads kept its bytes; the
                // rest of the tree landed as empty-but-present markers.
                assert_eq!(
                    fs::read_to_string(root.join("Cargo.toml")).unwrap(),
                    "[package]\nname = \"dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                );
                assert!(fs::exists(root.join("src/lib.rs")));
                assert!(fs::exists(root.join("sub/file.txt")));
                assert!(fs::exists(root.join("link.rs")));
            }
            _ => panic!("expected the package to be downloaded"),
        }
        fs::replace_vfs(None);
    }

    /// The resolver polls queries on one source concurrently, so
    /// concurrent `update()`s interleave at every `.await`. While the
    /// first is parked inside `resolve_sha`'s ls-remote, the second
    /// completes and writes the results: a `RefCell` borrow held across
    /// that await used to panic `RefCell already borrowed` in
    /// `requested.replace` — a trap that on wasm left the request's
    /// promise pending forever (the production "code had hung").
    #[test]
    fn concurrent_updates_on_one_source_do_not_deadlock() {
        use futures::channel::oneshot;

        fs::set_vfs(Rc::new(crate::util::fs::MemoryVfs::new()));
        let sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let pkt = |payload: &str| format!("{:04x}{payload}", payload.len() + 4);
        let ls_remote = format!(
            "{}{}{}{}{}",
            pkt("# service=git-upload-pack\n"),
            "0000",
            pkt("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HEAD\0multi_ack thin-pack\n"),
            pkt(&format!("{sha} refs/heads/main\n")),
            "0000"
        );

        /// Answers ls-remote immediately except the first call, which
        /// parks until the test opens `gate`.
        struct GateHttp {
            ls_remote: Vec<u8>,
            gate: std::cell::Cell<Option<oneshot::Receiver<()>>>,
        }
        impl crate::util::network::http_async::HttpClient for GateHttp {
            fn request<'a>(
                &'a self,
                request: http::Request<Vec<u8>>,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = CargoResult<http::Response<Vec<u8>>>> + 'a>,
            > {
                let _ = request;
                Box::pin(async move {
                    if let Some(gate) = self.gate.take() {
                        let _ = gate.await;
                    }
                    Ok(http::Response::builder()
                        .status(200)
                        .body(self.ls_remote.clone())
                        .unwrap())
                })
            }
        }

        let (gate_send, gate_recv) = oneshot::channel();
        let mut gctx = GlobalContext::default().unwrap();
        gctx.set_http(crate::util::network::http_async::Client::new(Rc::new(
            GateHttp {
                ls_remote: ls_remote.into_bytes(),
                gate: std::cell::Cell::new(Some(gate_recv)),
            },
        )));
        let url = Url::parse("https://github.com/zed-industries/wprcontrol").unwrap();
        let source_id = SourceId::for_git(&url, GitReference::Branch("main".to_string())).unwrap();
        let source = Rc::new(
            GitTreeSource::new(source_id, &gctx)
                .unwrap()
                .expect("github source"),
        );

        // The checkout already exists, so `update` skips the fetch loop —
        // the collision being tested is the parked `resolve_sha` borrow
        // versus the second update's `replace`, not the fetch gate.
        let ident = ident_shallow(&source_id);
        let checkout = gctx
            .git_checkouts_path()
            .join(&ident)
            .into_path_unlocked()
            .join(format!("wprcontrol-{sha}"));
        fs::write(
            checkout.join("Cargo.toml"),
            b"[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(checkout.join("src/lib.rs"), b"pub fn f() {}").unwrap();

        // Drive the two updates by hand, the interleave the resolver's
        // poller produces: the first parks in `ls_remote` holding (before
        // the fix) a borrow of `requested`; the second then runs `update`
        // to completion in one poll — its `requested.replace` collided
        // with the parked borrow.
        let mut first = Box::pin(source.update());
        let mut second = Box::pin(source.update());
        let waker = futures::task::noop_waker_ref();
        let mut cx = std::task::Context::from_waker(waker);
        assert!(first.as_mut().poll(&mut cx).is_pending());
        match second.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(result) => result.expect("second update failed"),
            std::task::Poll::Pending => {
                panic!("second update blocked while the first was parked")
            }
        }
        gate_send.send(()).unwrap();
        loop {
            match first.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(result) => {
                    result.expect("first update failed");
                    break;
                }
                std::task::Poll::Pending => {}
            }
        }
        fs::replace_vfs(None);
    }

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
        fs::set_vfs(Rc::new(crate::util::fs::MemoryVfs::new()));
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
        fs::replace_vfs(None);
    }

    /// A claim groups only the waiters inside one resolve's ambient VFS:
    /// the same checkout path under a different resolve's tree is its
    /// own owner, so a request abandoned mid-fetch can never strand a
    /// later resolve on a claim nobody releases.
    #[test]
    fn checkout_fetch_claims_are_scoped_to_the_ambient_vfs() {
        let key = PathBuf::from("/checkout/notify-abc");
        fs::set_vfs(Rc::new(crate::util::fs::MemoryVfs::new()));
        let CheckoutFetchClaim::Owner(first) = CheckoutFetch::acquire(&key) else {
            panic!("first acquire owns the fetch")
        };
        fs::set_vfs(Rc::new(crate::util::fs::MemoryVfs::new()));
        assert!(
            matches!(CheckoutFetch::acquire(&key), CheckoutFetchClaim::Owner(_)),
            "a different resolve's VFS owns the same checkout path"
        );
        fs::replace_vfs(None);
        drop(first);
    }

    /// An owner a cancelled request never drops must not pin the whole
    /// checkout tree: the claim holds a `Weak`, so once the resolve's
    /// last `Rc` is gone the entry's tree is freed and the next
    /// `acquire` prunes the dead claim.
    #[test]
    fn checkout_fetch_prunes_abandoned_claims() {
        let key = PathBuf::from("/checkout/notify-abc");
        let vfs: Rc<dyn fs::Vfs> = Rc::new(crate::util::fs::MemoryVfs::new());
        let vfs_weak = Rc::downgrade(&vfs);
        fs::set_vfs(vfs.clone());
        let CheckoutFetchClaim::Owner(first) = CheckoutFetch::acquire(&key) else {
            panic!("first acquire owns the fetch")
        };
        // An abandoned request's owner is never dropped.
        std::mem::forget(first);
        fs::replace_vfs(None);
        drop(vfs);
        // The claim's `Weak` can no longer reach the tree — a `Rc` here
        // would have kept every unpacked file alive for the isolate.
        assert!(vfs_weak.upgrade().is_none());
        fs::set_vfs(Rc::new(crate::util::fs::MemoryVfs::new()));
        let CheckoutFetchClaim::Owner(fresh) = CheckoutFetch::acquire(&key) else {
            panic!("a fresh resolve owns the same checkout path")
        };
        // The fresh acquire pruned the dead claim — only its own entry
        // remains.
        assert_eq!(CHECKOUT_FETCHES.with(|f| f.borrow().len()), 1);
        drop(fresh);
        fs::replace_vfs(None);
    }
}
