//! GitHub repository tree fetch: a codeload tarball plus every
//! submodule's own tarball, checked out at the commit the parent tree
//! pins it at.
//!
//! `git clone --recurse-submodules` is not available to the projects
//! lane — a wasm32 worker carries no git binary, and the harness wants
//! the same path natively — so the checkout is reproduced over HTTPS:
//!
//! 1. `GET {repo}.git/info/refs?service=git-upload-pack` resolves `git_ref`
//!    to a commit sha the way git's own ls-remote would — the same pin is
//!    then used for the tarball and the gitlink lookups, so a ref moving
//!    mid-fetch cannot tear the tree.
//! 2. `GET https://codeload.github.com/{o}/{r}/tar.gz/{sha}` materializes
//!    the tracked tree — submodules included arrive as empty directories,
//!    because gitlinks carry no file payload.
//! 3. `.gitmodules` names each submodule's `path`/`url`; the pinned
//!    commit comes from a protocol-v2 `fetch` for the commit with
//!    `filter=blob:none` — one `git-upload-pack` POST returning every
//!    tree under the commit, whose `mode 160000` entries are the
//!    gitlinks ([`crate::git_proto`]). The REST trees API is unusable
//!    here: unauthenticated `api.github.com` caps at 60 requests an hour
//!    per egress IP, a quota Cloudflare shares across every worker on
//!    it; `git-upload-pack` is the anonymous endpoint `git clone` uses.
//! 4. Each GitHub-hosted submodule is fetched as its own codeload tarball
//!    at the gitlink sha and laid over the empty directory; a submodule
//!    that itself lists submodules recurses the same way (depth-capped).
//!
//! Divergences from a real recursive checkout, all surfaced as
//! [`GithubTree::notes`]: `update = none` submodules are left empty (as
//! `git submodule update` leaves them), a submodule URL hosted anywhere
//! but github.com is skipped, and a gitlink missing from the parent tree
//! resolves nothing. A manifest that lives inside an unfetched submodule
//! then fails the resolve with cargo's own missing-member error — the
//! note carries the fetch-level reason.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use url::Url;

use crate::git_proto::{self, TreeEntry};
use crate::util::errors::CargoResult;
use crate::util::network::http_async::Client;
use crate::util::tarball::{self, TarPrefix};

/// `User-Agent` GitHub's REST API demands and crates.io-adjacent fetchers
/// set alike: the tool name and the repository that operates it.
pub const USER_AGENT: &str = concat!(
    "stow-resolve/",
    env!("CARGO_PKG_VERSION"),
    " (https://github.com/water-rs/stow)"
);

/// Deepest submodule nesting a checkout chases; past this the notes name
/// the path rather than recursing forever on a hostile tree.
const MAX_SUBMODULE_DEPTH: u32 = 8;

/// A repository's full source tree at one commit: unpacked file bytes
/// keyed by repo-relative path, submodule contents merged under their
/// paths.
pub struct GithubTree {
    /// `Cargo.toml`, `src/lib.rs`, … — every file the resolved commit
    /// tracked, including inside fetched submodules.
    pub files: BTreeMap<PathBuf, Vec<u8>>,
    /// The commit sha `git_ref` resolved to — what the tarballs were
    /// fetched at.
    pub commit: String,
    /// Fetch-level anomalies worth surfacing to the operator: unfetched
    /// submodules and the reason each was skipped.
    pub notes: Vec<String>,
}

/// Fetch `repo` (`owner/name`) at `git_ref` — branch, tag, `HEAD`, or a
/// commit sha — into [`GithubTree`].
pub async fn fetch_github_tree(
    client: &Client,
    repo: &str,
    git_ref: &str,
) -> CargoResult<GithubTree> {
    let root = GithubRepo::from_repo(repo)
        .with_context(|| format!("`{repo}` is not a github.com owner/repo"))?;
    let commit = resolve_ref(client, &root, git_ref).await?;
    let mut files = fetch_codeload(client, &root, &commit).await?;
    let mut notes = Vec::new();
    let mut trees = BTreeMap::new();
    fill_submodules(
        client,
        &mut files,
        &mut notes,
        &mut trees,
        &root,
        &commit,
        Path::new(""),
        0,
    )
    .await?;
    Ok(GithubTree {
        files,
        commit,
        notes,
    })
}

/// A `github.com` `owner/repo` pair — `from_url` accepts every form cargo
/// accepts for a git URL, plus scp-style `git@github.com:o/r.git`; a
/// `.gitmodules` `url` may additionally be repo-relative (`../x`).
#[derive(Debug, Clone)]
struct GithubRepo {
    owner: String,
    repo: String,
}

impl GithubRepo {
    /// Parse an `owner/name` string.
    fn from_repo(repo: &str) -> Option<GithubRepo> {
        let (owner, repo) = repo.split_once('/')?;
        if owner.is_empty() || repo.is_empty() || repo.contains('/') {
            return None;
        }
        Some(GithubRepo {
            owner: owner.to_owned(),
            repo: repo.to_owned(),
        })
    }

    /// Parse a git URL into its repo; `None` for non-GitHub hosts.
    fn from_url(url: &str) -> Option<GithubRepo> {
        // scp-style SSH (`git@github.com:owner/repo.git`) is not a URL —
        // normalize it before handing to `Url`.
        let url = url.strip_prefix("git@github.com:").map_or_else(
            || url.to_owned(),
            |rest| format!("https://github.com/{rest}"),
        );
        let parsed = Url::parse(url.as_str()).ok()?;
        match parsed.host_str() {
            Some("github.com") | Some("www.github.com") => {}
            _ => return None,
        }
        let mut segments = parsed.path_segments()?.filter(|s| !s.is_empty());
        let owner = segments.next()?;
        let repo = segments.next()?;
        if segments.next().is_some() {
            return None;
        }
        let repo = repo.strip_suffix(".git").unwrap_or(repo);
        if owner.is_empty() || repo.is_empty() {
            return None;
        }
        Some(GithubRepo {
            owner: owner.to_owned(),
            repo: repo.to_owned(),
        })
    }

    /// Resolve a `.gitmodules` `url` — absolute, or repo-relative
    /// (`../sibling.git`) against this repository.
    fn submodule_url(&self, url: &str) -> Option<GithubRepo> {
        if url.starts_with("../") || url.starts_with("./") {
            let base = format!("https://github.com/{}/{}/", self.owner, self.repo);
            let resolved = Url::parse(&base).ok()?.join(url).ok()?;
            return GithubRepo::from_url(resolved.as_str());
        }
        GithubRepo::from_url(url)
    }
}

/// `GET` `url` through the resolve client into bytes; a non-2xx status is
/// an error naming the fetched thing. Transport failures retry — a
/// codeload stream dropping mid-body is the ordinary case, and the lane
/// should not lose a repository to it.
async fn get(client: &Client, url: &str, what: &str) -> CargoResult<Vec<u8>> {
    const ATTEMPTS: u32 = 4;
    let mut last = anyhow!("no attempts made");
    for attempt in 1..=ATTEMPTS {
        let request = http::Request::get(url)
            .header("User-Agent", USER_AGENT)
            .header("Accept", "application/vnd.github+json")
            .body(Vec::new())?;
        match client.request(request).await {
            Ok(response) => {
                let (parts, body) = response.into_parts();
                if !(200..300).contains(&parts.status.as_u16()) {
                    bail!("failed to get {what} from `{url}`: HTTP {}", parts.status);
                }
                return Ok(body);
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

/// `GET` `url` as a streaming body — a repo tarball dwarfs the isolate's
/// memory, so it decodes on the wire like the git-dependency lane's
/// `get_stream`. Returns the body and Content-Length (the decompression
/// bound's compression-ratio input). Transport failures retry.
async fn get_stream(
    client: &Client,
    url: &str,
    what: &str,
) -> CargoResult<(crate::util::network::http_async::BodyStream, Option<u64>)> {
    const ATTEMPTS: u32 = 4;
    let mut last = anyhow!("no attempts made");
    for attempt in 1..=ATTEMPTS {
        let request = http::Request::get(url)
            .header("User-Agent", USER_AGENT)
            .header("Accept", "application/vnd.github+json")
            .body(Vec::new())?;
        match client.request_stream(request).await {
            Ok(response) => {
                let (parts, body) = response.into_parts();
                if !(200..300).contains(&parts.status.as_u16()) {
                    bail!("failed to get {what} from `{url}`: HTTP {}", parts.status);
                }
                let len = parts
                    .headers
                    .get(http::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok());
                return Ok((body, len));
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

/// Resolve `git_ref` to a commit sha over ls-remote: a full sha passes
/// through, `HEAD` and branches/tags hit the same advertisement git's own
/// remote negotiation reads.
async fn resolve_ref(client: &Client, repo: &GithubRepo, git_ref: &str) -> CargoResult<String> {
    if is_full_sha(git_ref) {
        return Ok(git_ref.to_owned());
    }
    let url = format!(
        "https://github.com/{}/{}/info/refs?service=git-upload-pack",
        repo.owner, repo.repo
    );
    let body = get(
        client,
        &url,
        &format!("git refs of `{}/{}`", repo.owner, repo.repo),
    )
    .await?;
    let text = String::from_utf8(body).context("invalid UTF-8 in git ls-remote response")?;
    let refs = git_proto::parse_ls_remote(&text);
    let find = |name: &str| {
        refs.iter()
            .find(|(_, r)| r == name)
            .map(|(sha, _)| sha.clone())
    };
    let sha = if git_ref == "HEAD" {
        find("HEAD")
    } else {
        find(&format!("refs/heads/{git_ref}"))
            .or_else(|| find(&format!("refs/tags/{git_ref}^{{}}")))
            .or_else(|| find(&format!("refs/tags/{git_ref}")))
            .or_else(|| git_ref.strip_prefix("refs/").and_then(find))
    };
    sha.ok_or_else(|| {
        anyhow!(
            "reference `{git_ref}` not found in `{}/{}`",
            repo.owner,
            repo.repo
        )
    })
}

/// `GET https://codeload.github.com/{o}/{r}/tar.gz/{sha}`, decoded on the
/// wire by [`crate::util::tarball::collect_tar_gz`] — the same bound and
/// link materialization the git-dependency lane gets.
async fn fetch_codeload(
    client: &Client,
    repo: &GithubRepo,
    sha: &str,
) -> CargoResult<BTreeMap<PathBuf, Vec<u8>>> {
    let url = format!(
        "https://codeload.github.com/{}/{}/tar.gz/{sha}",
        repo.owner, repo.repo
    );
    let (body, len) = get_stream(
        client,
        &url,
        &format!("tree of `{}/{}`", repo.owner, repo.repo),
    )
    .await?;
    tarball::collect_tar_gz(
        body,
        TarPrefix::FirstComponent,
        tarball::unpack_size_bound(len),
        tarball::MAX_RESOLVE_TREE_BYTES,
    )
    .await
    .with_context(|| format!("unpack `{url}`"))
}

/// One `.gitmodules` `[submodule]` section.
struct Submodule {
    path: String,
    url: String,
    /// `update = none` opts a submodule out of `git submodule update` —
    /// the recursive checkout skips it too.
    update_none: bool,
}

/// Parse `.gitmodules` — the git-config INI subset a checked-in file
/// uses: `[submodule "<name>"]` sections carrying `path`/`url`/`update`.
fn parse_gitmodules(text: &str) -> Vec<Submodule> {
    let mut out = Vec::new();
    let mut current: Option<Submodule> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            if let Some(sub) = current.take() {
                out.push(sub);
            }
            current = if line.starts_with("[submodule ") && line.ends_with(']') {
                Some(Submodule {
                    path: String::new(),
                    url: String::new(),
                    update_none: false,
                })
            } else {
                None
            };
            continue;
        }
        let Some(sub) = current.as_mut() else {
            continue;
        };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "path" => sub.path = value.trim().to_owned(),
            "url" => sub.url = value.trim().to_owned(),
            "update" => sub.update_none = value.trim() == "none",
            _ => {}
        }
    }
    if let Some(sub) = current {
        out.push(sub);
    }
    out
}

/// Recursive `path → entry` maps, memoized per `(repo, commit)` — each
/// costs one [`git_proto::fetch_commit_tree`] POST and sibling
/// submodules read the same map.
type TreeCache = BTreeMap<(String, String), Result<BTreeMap<PathBuf, TreeEntry>, String>>;

/// The gitlink commit `path` points at inside `repo`@`commit` — `None`
/// when no `mode 160000` entry sits there (a real directory, or
/// nothing). The entry map is the whole recursive tree of the commit,
/// fetched once per repository.
async fn gitlink_sha(
    client: &Client,
    trees: &mut TreeCache,
    repo: &GithubRepo,
    commit: &str,
    path: &Path,
) -> CargoResult<Option<String>> {
    let key = (format!("{}/{}", repo.owner, repo.repo), commit.to_owned());
    if !trees.contains_key(&key) {
        let result = git_proto::fetch_commit_tree(client, &repo.owner, &repo.repo, commit)
            .await
            .map_err(|error| format!("{error:#}"));
        trees.insert(key.clone(), result);
    }
    let entries = match &trees[&key] {
        Ok(entries) => entries,
        Err(error) => bail!("{error}"),
    };
    Ok(entries
        .get(path)
        .filter(|entry| entry.mode == 0o160000)
        .map(|entry| entry.sha.clone()))
}

/// Fill every submodule a `.gitmodules` under `dir` declares: fetch the
/// gitlink sha out of `repo`@`commit`'s tree, fetch that repo's codeload
/// tarball at it, lay it under the submodule path, and recurse for
/// submodules the submodule itself declares.
async fn fill_submodules(
    client: &Client,
    files: &mut BTreeMap<PathBuf, Vec<u8>>,
    notes: &mut Vec<String>,
    trees: &mut TreeCache,
    repo: &GithubRepo,
    commit: &str,
    dir: &Path,
    depth: u32,
) -> CargoResult<()> {
    let gitmodules_path = if dir.as_os_str().is_empty() {
        PathBuf::from(".gitmodules")
    } else {
        dir.join(".gitmodules")
    };
    let Some(text) = files.get(&gitmodules_path) else {
        return Ok(());
    };
    let text = String::from_utf8(text.clone())
        .with_context(|| format!("{} is not UTF-8", gitmodules_path.display()))?;
    for submodule in parse_gitmodules(&text) {
        let path = dir.join(&submodule.path);
        let display = path.display().to_string();
        if submodule.update_none {
            notes.push(format!(
                "submodule `{display}` sets `update = none` — skipped"
            ));
            continue;
        }
        if submodule.path.is_empty() || submodule.url.is_empty() {
            notes.push(format!("submodule `{display}` lacks path/url — skipped"));
            continue;
        }
        let Some(sha) =
            gitlink_sha(client, trees, repo, commit, Path::new(&submodule.path)).await?
        else {
            notes.push(format!(
                "submodule `{display}` has no gitlink in the parent tree — skipped"
            ));
            continue;
        };
        let Some(sub_repo) = repo.submodule_url(&submodule.url) else {
            notes.push(format!(
                "submodule `{display}` is not hosted on github.com ({}) — skipped",
                submodule.url
            ));
            continue;
        };
        let sub_files = match fetch_codeload(client, &sub_repo, &sha).await {
            Ok(sub_files) => sub_files,
            Err(error) => {
                notes.push(format!("submodule `{display}` fetch failed: {error:#}"));
                continue;
            }
        };
        // A submodule path never lists plain components above itself —
        // the unpack lands under `path/`.
        for (rel, data) in sub_files {
            files.insert(path.join(rel), data);
        }
        if depth + 1 >= MAX_SUBMODULE_DEPTH {
            notes.push(format!("submodule `{display}` nested past the depth cap"));
            continue;
        }
        Box::pin(fill_submodules(
            client,
            files,
            notes,
            trees,
            &sub_repo,
            &sha,
            &path,
            depth + 1,
        ))
        .await?;
    }
    Ok(())
}

/// The manifest the projects lane resolves: the shallowest `Cargo.lock`
/// whose directory also carries `Cargo.toml` — a lockfile roots the
/// workspace it pins — else the shallowest `Cargo.toml` at all.
pub fn select_manifest(files: &BTreeMap<PathBuf, Vec<u8>>) -> Option<PathBuf> {
    let manifest_dirs: BTreeMap<PathBuf, PathBuf> = files
        .keys()
        .filter(|path| path.file_name().and_then(|n| n.to_str()) == Some("Cargo.toml"))
        .map(|path| {
            (
                path.parent().map_or_else(PathBuf::new, Path::to_path_buf),
                path.clone(),
            )
        })
        .collect();
    // Shallowest lockfile first, lexicographic within a depth — the
    // order the admin lane's admission used.
    let mut lock_dirs: Vec<PathBuf> = files
        .keys()
        .filter(|path| path.file_name().and_then(|n| n.to_str()) == Some("Cargo.lock"))
        .filter_map(|path| path.parent().map(Path::to_path_buf))
        .collect();
    lock_dirs.sort_by(|a, b| {
        a.components()
            .count()
            .cmp(&b.components().count())
            .then_with(|| a.cmp(b))
    });
    for dir in &lock_dirs {
        if let Some(manifest) = manifest_dirs.get(dir) {
            return Some(manifest.clone());
        }
    }
    manifest_dirs
        .into_iter()
        .min_by_key(|(dir, _)| (dir.components().count(), dir.clone()))
        .map(|(_, manifest)| manifest)
}

fn is_full_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gitmodules_parse() {
        let text = concat!(
            "[submodule \"libs/hbb_common\"]\n",
            "\tpath = libs/hbb_common\n",
            "\turl = https://github.com/rustdesk/hbb_common.git\n",
            "[submodule \"tests/none\"]\n",
            "\tpath = tests/none\n",
            "\turl = ../sibling.git\n",
            "\tupdate = none\n",
        );
        let subs = parse_gitmodules(text);
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].path, "libs/hbb_common");
        assert_eq!(subs[0].url, "https://github.com/rustdesk/hbb_common.git");
        assert!(!subs[0].update_none);
        assert_eq!(subs[1].path, "tests/none");
        assert!(subs[1].update_none);
    }

    #[test]
    fn submodule_url_forms() {
        let root = GithubRepo {
            owner: "o".into(),
            repo: "r".into(),
        };
        for (url, expected) in [
            ("https://github.com/a/b", Some(("a", "b"))),
            ("https://github.com/a/b.git", Some(("a", "b"))),
            ("ssh://git@github.com/a/b.git", Some(("a", "b"))),
            ("git@github.com:a/b.git", Some(("a", "b"))),
            ("../b.git", Some(("o", "b"))),
            ("https://gitlab.com/a/b", None),
        ] {
            let got = root.submodule_url(url);
            let got = got.map(|r| (r.owner.clone(), r.repo.clone()));
            assert_eq!(
                got,
                expected.map(|(o, r)| (o.to_owned(), r.to_owned())),
                "{url}"
            );
        }
    }
}
