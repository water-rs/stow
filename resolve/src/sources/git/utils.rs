//! Utilities for handling git repositories, mainly around
//! authentication/cloning.

use crate::core::GitReference;
use crate::sources::git::fetch::RemoteKind;
use crate::sources::git::oxide;
use crate::sources::git::oxide::cargo_config_to_gitoxide_overrides;
use crate::util::HumanBytes;
use crate::util::errors::CargoResult;
use crate::util::{GlobalContext, MetricsCounter, Progress, network};

use crate::util::paths;
use anyhow::{Context as _, anyhow};
use git2::{ErrorClass, ObjectType, Oid};
use http::{Request, StatusCode};
use tracing::debug;
use url::Url;

use std::path::Path;
use std::process::Command;
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Resolves [`GitReference`] to an object ID with objects the `repo` currently has.
pub fn resolve_ref(gitref: &GitReference, repo: &git2::Repository) -> CargoResult<git2::Oid> {
    let id = match gitref {
        // Note that we resolve the named tag here in sync with where it's
        // fetched into via `fetch` below.
        GitReference::Tag(s) => (|| -> CargoResult<git2::Oid> {
            let refname = format!("refs/remotes/origin/tags/{}", s);
            let id = repo.refname_to_id(&refname)?;
            let obj = repo.find_object(id, None)?;
            let obj = obj.peel(ObjectType::Commit)?;
            Ok(obj.id())
        })()
        .with_context(|| format!("failed to find tag `{}`", s))?,

        // Resolve the remote name since that's all we're configuring in
        // `fetch` below.
        GitReference::Branch(s) => {
            let name = format!("origin/{}", s);
            let b = repo
                .find_branch(&name, git2::BranchType::Remote)
                .with_context(|| format!("failed to find branch `{}`", s))?;
            b.get()
                .target()
                .ok_or_else(|| anyhow::format_err!("branch `{}` did not have a target", s))?
        }

        // We'll be using the HEAD commit
        GitReference::DefaultBranch => {
            let head_id = repo.refname_to_id("refs/remotes/origin/HEAD")?;
            let head = repo.find_object(head_id, None)?;
            head.peel(ObjectType::Commit)?.id()
        }

        GitReference::Rev(s) => {
            let obj = repo.revparse_single(s)?;
            match obj.as_tag() {
                Some(tag) => tag.target_id(),
                None => obj.id(),
            }
        }
    };
    Ok(id)
}

/// Prepare the authentication callbacks for cloning a git repository.
///
/// The main purpose of this function is to construct the "authentication
/// callback" which is used to clone a repository. This callback will attempt to
/// find the right authentication on the system (without user input) and will
/// guide libgit2 in doing so.
///
/// The callback is provided `allowed` types of credentials, and we try to do as
/// much as possible based on that:
///
/// * Prioritize SSH keys from the local ssh agent as they're likely the most
///   reliable. The username here is prioritized from the credential
///   callback, then from whatever is configured in git itself, and finally
///   we fall back to the generic user of `git`.
///
/// * If a username/password is allowed, then we fallback to git2-rs's
///   implementation of the credential helper. This is what is configured
///   with `credential.helper` in git, and is the interface for the macOS
///   keychain, for example.
///
/// * After the above two have failed, we just kinda grapple attempting to
///   return *something*.
///
/// If any form of authentication fails, libgit2 will repeatedly ask us for
/// credentials until we give it a reason to not do so. To ensure we don't
/// just sit here looping forever we keep track of authentications we've
/// attempted and we don't try the same ones again.
fn with_authentication<T, F>(
    gctx: &GlobalContext,
    url: &str,
    cfg: &git2::Config,
    mut f: F,
) -> CargoResult<T>
where
    F: FnMut(&mut git2::Credentials<'_>) -> CargoResult<T>,
{
    let mut cred_helper = git2::CredentialHelper::new(url);
    cred_helper.config(cfg);

    let mut ssh_username_requested = false;
    let mut cred_helper_bad = None;
    let mut ssh_agent_attempts = Vec::new();
    let mut any_attempts = false;
    let mut tried_sshkey = false;
    let mut url_attempt = None;

    let orig_url = url;
    let mut res = f(&mut |url, username, allowed| {
        any_attempts = true;
        if url != orig_url {
            url_attempt = Some(url.to_string());
        }
        // libgit2's "USERNAME" authentication actually means that it's just
        // asking us for a username to keep going. This is currently only really
        // used for SSH authentication and isn't really an authentication type.
        // The logic currently looks like:
        //
        //      let user = ...;
        //      if (user.is_null())
        //          user = callback(USERNAME, null, ...);
        //
        //      callback(SSH_KEY, user, ...)
        //
        // So if we're being called here then we know that (a) we're using ssh
        // authentication and (b) no username was specified in the URL that
        // we're trying to clone. We need to guess an appropriate username here,
        // but that may involve a few attempts. Unfortunately we can't switch
        // usernames during one authentication session with libgit2, so to
        // handle this we bail out of this authentication session after setting
        // the flag `ssh_username_requested`, and then we handle this below.
        if allowed.contains(git2::CredentialType::USERNAME) {
            debug_assert!(username.is_none());
            ssh_username_requested = true;
            return Err(git2::Error::from_str("gonna try usernames later"));
        }

        // An "SSH_KEY" authentication indicates that we need some sort of SSH
        // authentication. This can currently either come from the ssh-agent
        // process or from a raw in-memory SSH key. Cargo only supports using
        // ssh-agent currently.
        //
        // If we get called with this then the only way that should be possible
        // is if a username is specified in the URL itself (e.g., `username` is
        // Some), hence the unwrap() here. We try custom usernames down below.
        if allowed.contains(git2::CredentialType::SSH_KEY) && !tried_sshkey {
            // If ssh-agent authentication fails, libgit2 will keep
            // calling this callback asking for other authentication
            // methods to try. Make sure we only try ssh-agent once,
            // to avoid looping forever.
            tried_sshkey = true;
            let username = username.unwrap();
            debug_assert!(!ssh_username_requested);
            ssh_agent_attempts.push(username.to_string());
            return git2::Cred::ssh_key_from_agent(username);
        }

        // Sometimes libgit2 will ask for a username/password in plaintext. This
        // is where Cargo would have an interactive prompt if we supported it,
        // but we currently don't! Right now the only way we support fetching a
        // plaintext password is through the `credential.helper` support, so
        // fetch that here.
        //
        // If ssh-agent authentication fails, libgit2 will keep calling this
        // callback asking for other authentication methods to try. Check
        // cred_helper_bad to make sure we only try the git credential helper
        // once, to avoid looping forever.
        if allowed.contains(git2::CredentialType::USER_PASS_PLAINTEXT) && cred_helper_bad.is_none()
        {
            let r = git2::Cred::credential_helper(cfg, url, username);
            cred_helper_bad = Some(r.is_err());
            return r;
        }

        // I'm... not sure what the DEFAULT kind of authentication is, but seems
        // easy to support?
        if allowed.contains(git2::CredentialType::DEFAULT) {
            return git2::Cred::default();
        }

        // Whelp, we tried our best
        Err(git2::Error::from_str("no authentication methods succeeded"))
    });

    // Ok, so if it looks like we're going to be doing ssh authentication, we
    // want to try a few different usernames as one wasn't specified in the URL
    // for us to use. In order, we'll try:
    //
    // * A credential helper's username for this URL, if available.
    // * This account's username.
    // * "git"
    //
    // We have to restart the authentication session each time (due to
    // constraints in libssh2 I guess? maybe this is inherent to ssh?), so we
    // call our callback, `f`, in a loop here.
    if ssh_username_requested {
        debug_assert!(res.is_err());
        let mut attempts = vec![String::from("git")];
        if let Ok(s) = gctx.get_env("USER").or_else(|_| gctx.get_env("USERNAME")) {
            attempts.push(s.to_string());
        }
        if let Some(ref s) = cred_helper.username {
            attempts.push(s.clone());
        }

        while let Some(s) = attempts.pop() {
            // We should get `USERNAME` first, where we just return our attempt,
            // and then after that we should get `SSH_KEY`. If the first attempt
            // fails we'll get called again, but we don't have another option so
            // we bail out.
            let mut attempts = 0;
            res = f(&mut |_url, username, allowed| {
                if allowed.contains(git2::CredentialType::USERNAME) {
                    return git2::Cred::username(&s);
                }
                if allowed.contains(git2::CredentialType::SSH_KEY) {
                    debug_assert_eq!(Some(&s[..]), username);
                    attempts += 1;
                    if attempts == 1 {
                        ssh_agent_attempts.push(s.to_string());
                        return git2::Cred::ssh_key_from_agent(&s);
                    }
                }
                Err(git2::Error::from_str("no authentication methods succeeded"))
            });

            // If we made two attempts then that means:
            //
            // 1. A username was requested, we returned `s`.
            // 2. An ssh key was requested, we returned to look up `s` in the
            //    ssh agent.
            // 3. For whatever reason that lookup failed, so we were asked again
            //    for another mode of authentication.
            //
            // Essentially, if `attempts == 2` then in theory the only error was
            // that this username failed to authenticate (e.g., no other network
            // errors happened). Otherwise something else is funny so we bail
            // out.
            if attempts != 2 {
                break;
            }
        }
    }
    let mut err = match res {
        Ok(e) => return Ok(e),
        Err(e) => e,
    };

    // In the case of an authentication failure (where we tried something) then
    // we try to give a more helpful error message about precisely what we
    // tried.
    if any_attempts {
        let mut msg = "failed to authenticate when downloading \
                       repository"
            .to_string();

        if let Some(attempt) = &url_attempt {
            if url != attempt {
                msg.push_str(": ");
                msg.push_str(attempt);
            }
        }
        msg.push('\n');
        if !ssh_agent_attempts.is_empty() {
            let names = ssh_agent_attempts
                .iter()
                .map(|s| format!("`{}`", s))
                .collect::<Vec<_>>()
                .join(", ");
            msg.push_str(&format!(
                "\n* attempted ssh-agent authentication, but \
                 no usernames succeeded: {}",
                names
            ));
        }
        if let Some(failed_cred_helper) = cred_helper_bad {
            if failed_cred_helper {
                msg.push_str(
                    "\n* attempted to find username/password via \
                     git's `credential.helper` support, but failed",
                );
            } else {
                msg.push_str(
                    "\n* attempted to find username/password via \
                     `credential.helper`, but maybe the found \
                     credentials were incorrect",
                );
            }
        }
        msg.push_str("\n\n");
        msg.push_str("if the git CLI succeeds then `net.git-fetch-with-cli` may help here\n");
        msg.push_str("https://doc.rust-lang.org/cargo/reference/config.html#netgit-fetch-with-cli");
        err = err.context(msg);

        // Otherwise if we didn't even get to the authentication phase them we may
        // have failed to set up a connection, in these cases hint on the
        // `net.git-fetch-with-cli` configuration option.
    } else if let Some(e) = err.downcast_ref::<git2::Error>() {
        match e.class() {
            ErrorClass::Net
            | ErrorClass::Ssl
            | ErrorClass::Submodule
            | ErrorClass::FetchHead
            | ErrorClass::Ssh
            | ErrorClass::Http => {
                let msg = format!(
                    concat!(
                        "network failure seems to have happened\n",
                        "if a proxy or similar is necessary `net.git-fetch-with-cli` may help here\n",
                        "https://doc.rust-lang.org/cargo/reference/config.html#netgit-fetch-with-cli",
                        "{}"
                    ),
                    note_github_pull_request(url).unwrap_or_default()
                );
                err = err.context(msg);
            }
            ErrorClass::Callback => {
                // This unwraps the git2 error. We're using the callback error
                // specifically to convey errors from Rust land through the C
                // callback interface. We don't need the `; class=Callback
                // (26)` that gets tacked on to the git2 error message.
                err = anyhow::format_err!("{}", e.message());
            }
            _ => {}
        }
    }

    Err(err)
}

///
/// The main purpose of this function is to construct everything before a fetch.
/// This will attempt to setup a progress bar, the authentication for git,
/// ssh known hosts check, and the network retry mechanism.
///
/// The callback is provided a fetch options, which can be used by the actual
/// git fetch.
pub fn with_fetch_options(
    git_config: &git2::Config,
    url: &str,
    gctx: &GlobalContext,
    cb: &mut dyn FnMut(git2::FetchOptions<'_>) -> CargoResult<()>,
) -> CargoResult<()> {
    let mut progress = Progress::new("Fetch", gctx);
    let ssh_config = gctx.net_config()?.ssh.as_ref();
    let config_known_hosts = ssh_config.and_then(|ssh| ssh.known_hosts.as_ref());
    let diagnostic_home_config = gctx.diagnostic_home_config();
    network::retry::with_retry(gctx, || {
        // Hack: libgit2 disallows overriding the error from check_cb since v1.8.0,
        // so we store the error additionally and unwrap it later
        let mut check_cb_result = Ok(());
        let auth_result = with_authentication(gctx, url, git_config, |f| {
            let port = Url::parse(url).ok().and_then(|url| url.port());
            let mut last_update = Instant::now();
            let mut rcb = git2::RemoteCallbacks::new();
            // We choose `N=10` here to make a `300ms * 10slots ~= 3000ms`
            // sliding window for tracking the data transfer rate (in bytes/s).
            let mut counter = MetricsCounter::<10>::new(0, last_update);
            rcb.credentials(f);
            rcb.certificate_check(|cert, host| {
                match super::known_hosts::certificate_check(
                    gctx,
                    cert,
                    host,
                    port,
                    config_known_hosts,
                    &diagnostic_home_config,
                ) {
                    Ok(status) => Ok(status),
                    Err(e) => {
                        check_cb_result = Err(e);
                        // This is not really used because it'll be overridden by libgit2
                        // See https://github.com/libgit2/libgit2/commit/9a9f220119d9647a352867b24b0556195cb26548
                        Err(git2::Error::from_str(
                            "invalid or unknown remote ssh hostkey",
                        ))
                    }
                }
            });
            rcb.transfer_progress(|stats| {
                let indexed_deltas = stats.indexed_deltas();
                let msg = if indexed_deltas > 0 {
                    // Resolving deltas.
                    format!(
                        ", ({}/{}) resolving deltas",
                        indexed_deltas,
                        stats.total_deltas()
                    )
                } else {
                    // Receiving objects.
                    //
                    // # Caveat
                    //
                    // Progress bar relies on git2 calling `transfer_progress`
                    // to update its transfer rate, but we cannot guarantee a
                    // periodic call of that callback. Thus if we don't receive
                    // any data for, say, 10 seconds, the rate will get stuck
                    // and never go down to 0B/s.
                    // In the future, we need to find away to update the rate
                    // even when the callback is not called.
                    let now = Instant::now();
                    // Scrape a `received_bytes` to the counter every 300ms.
                    if now - last_update > Duration::from_millis(300) {
                        counter.add(stats.received_bytes(), now);
                        last_update = now;
                    }
                    let rate = HumanBytes(counter.rate() as u64);
                    format!(", {rate:.2}/s")
                };
                progress
                    .tick(stats.indexed_objects(), stats.total_objects(), &msg)
                    .is_ok()
            });

            // Create a local anonymous remote in the repository to fetch the
            // url
            let mut opts = git2::FetchOptions::new();
            opts.remote_callbacks(rcb);
            cb(opts)
        });
        if auth_result.is_err() {
            check_cb_result?;
        }
        auth_result?;
        Ok(())
    })
}

/// Attempts to fetch the given git `reference` for a Git repository.
///
/// This is the main entry for git clone/fetch. It does the followings:
///
/// * Turns [`GitReference`] into refspecs accordingly.
/// * Dispatches `git fetch` using libgit2, gitoxide, or git CLI.
///
/// The `remote_url` argument is the git remote URL where we want to fetch from.
///
/// The `remote_kind` argument is a thing for [`-Zgitoxide`] shallow clones
/// at this time. It could be extended when libgit2 supports shallow clones.
///
/// [`-Zgitoxide`]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html#gitoxide
pub fn fetch(
    repo: &mut git2::Repository,
    remote_url: &str,
    manifest_reference: &GitReference,
    locked_reference: &GitReference,
    gctx: &GlobalContext,
    remote_kind: RemoteKind,
) -> CargoResult<()> {
    if let Some(offline_flag) = gctx.offline_flag() {
        anyhow::bail!(
            "attempting to update a git repository, but {offline_flag} \
             was specified"
        )
    }

    let shallow = remote_kind.to_shallow_setting(repo.is_shallow(), gctx);

    // Flag to keep track if the rev is a full commit hash
    let mut fast_path_rev: bool = false;

    let oid_to_fetch = match github_fast_path(repo, remote_url, locked_reference, gctx) {
        Ok(FastPathRev::UpToDate) => return Ok(()),
        Ok(FastPathRev::NeedsFetch(rev)) => Some(rev),
        Ok(FastPathRev::Indeterminate) => None,
        Err(e) => {
            debug!("failed to check github {:?}", e);
            None
        }
    };

    maybe_gc_repo(repo, gctx)?;

    clean_repo_temp_files(repo);

    // Translate the reference desired here into an actual list of refspecs
    // which need to get fetched. Additionally record if we're fetching tags.
    let mut refspecs = Vec::new();
    let mut tags = false;
    // The `+` symbol on the refspec means to allow a forced (fast-forward)
    // update which is needed if there is ever a force push that requires a
    // fast-forward.
    match locked_reference {
        // For branches and tags we can fetch simply one reference and copy it
        // locally, no need to fetch other branches/tags.
        GitReference::Branch(b) => {
            refspecs.push(format!("+refs/heads/{0}:refs/remotes/origin/{0}", b));
        }

        GitReference::Tag(t) => {
            refspecs.push(format!("+refs/tags/{0}:refs/remotes/origin/tags/{0}", t));
        }

        GitReference::DefaultBranch => {
            refspecs.push(String::from("+HEAD:refs/remotes/origin/HEAD"));
        }

        GitReference::Rev(rev) => {
            if rev.starts_with("refs/") {
                refspecs.push(format!("+{0}:{0}", rev));
            } else if let Some(oid_to_fetch) = oid_to_fetch {
                fast_path_rev = true;
                refspecs.push(format!("+{0}:refs/commit/{0}", oid_to_fetch));
            } else if !matches!(shallow, gix::remote::fetch::Shallow::NoChange)
                && rev_to_oid(rev).is_some()
            {
                // There is a specific commit to fetch and we will do so in shallow-mode only
                // to not disturb the previous logic.
                // Note that with typical settings for shallowing, we will just fetch a single `rev`
                // as single commit.
                // The reason we write to `refs/remotes/origin/HEAD` is that it's of special significance
                // when during `GitReference::resolve()`, but otherwise it shouldn't matter.
                refspecs.push(format!("+{0}:refs/remotes/origin/HEAD", rev));
            } else if let GitReference::Rev(rev) = manifest_reference
                && rev.starts_with("refs/")
            {
                // If the lockfile has a commit. we can't directly fetch it (unless we're talking
                // to GitHub), so we fetch the ref associated with it from the manifest.
                refspecs.push(format!("+{0}:{0}", rev));
            } else {
                // We don't know what the rev will point to. To handle this
                // situation we fetch all branches and tags, and then we pray
                // it's somewhere in there.
                refspecs.push(String::from("+refs/heads/*:refs/remotes/origin/*"));
                refspecs.push(String::from("+HEAD:refs/remotes/origin/HEAD"));
                tags = true;
            }
        }
    }

    debug!("doing a fetch for {remote_url}");
    let result = if gctx.cli_unstable().gitoxide.map_or(false, |git| git.fetch) {
        fetch_with_gitoxide(repo, remote_url, refspecs, tags, shallow, gctx)
    } else {
        fetch_with_libgit2(repo, remote_url, refspecs, tags, shallow, gctx)
    };

    if fast_path_rev {
        if let Some(oid) = oid_to_fetch {
            return result.with_context(|| format!("revision {} not found", oid));
        }
    }
    result
}

/// `gitoxide` uses shallow locks to assure consistency when fetching to and to avoid races, and to write
/// files atomically.
/// Cargo has its own lock files and doesn't need that mechanism for race protection, so a stray lock means
/// a signal interrupted a previous shallow fetch and doesn't mean a race is happening.
fn has_shallow_lock_file(err: &crate::sources::git::fetch::Error) -> bool {
    matches!(
        err,
        gix::env::collate::fetch::Error::Fetch(gix::remote::fetch::Error::Fetch(
            gix::protocol::fetch::Error::LockShallowFile(_)
        ))
    )
}

fn fetch_with_gitoxide(
    repo: &mut git2::Repository,
    remote_url: &str,
    refspecs: Vec<String>,
    tags: bool,
    shallow: gix::remote::fetch::Shallow,
    gctx: &GlobalContext,
) -> CargoResult<()> {
    debug!(target: "git-fetch", backend = "gitoxide");

    let git2_repo = repo;
    let config_overrides = cargo_config_to_gitoxide_overrides(gctx)?;
    let repo_reinitialized = AtomicBool::default();
    let res = oxide::with_retry_and_progress(
        git2_repo.path(),
        gctx,
        remote_url,
        &|repo_path,
          should_interrupt,
          mut progress,
          url_for_authentication: &mut dyn FnMut(&gix::bstr::BStr)| {
            // The `fetch` operation here may fail spuriously due to a corrupt
            // repository. It could also fail, however, for a whole slew of other
            // reasons (aka network related reasons). We want Cargo to automatically
            // recover from corrupt repositories, but we don't want Cargo to stomp
            // over other legitimate errors.
            //
            // Consequently we save off the error of the `fetch` operation and if it
            // looks like a "corrupt repo" error then we blow away the repo and try
            // again. If it looks like any other kind of error, or if we've already
            // blown away the repository, then we want to return the error as-is.
            loop {
                let res = oxide::open_repo(
                    repo_path,
                    config_overrides.clone(),
                    oxide::OpenMode::ForFetch,
                )
                .map_err(crate::sources::git::fetch::Error::from)
                .and_then(|repo| {
                    debug!("initiating fetch of {refspecs:?} from {remote_url}");
                    let url_for_authentication = &mut *url_for_authentication;
                    let remote = repo
                        .remote_at(remote_url)?
                        .with_fetch_tags(if tags {
                            gix::remote::fetch::Tags::All
                        } else {
                            gix::remote::fetch::Tags::Included
                        })
                        .with_refspecs(
                            refspecs.iter().map(|s| s.as_str()),
                            gix::remote::Direction::Fetch,
                        )
                        .map_err(crate::sources::git::fetch::Error::Other)?;
                    let url = remote
                        .url(gix::remote::Direction::Fetch)
                        .expect("set at init")
                        .to_owned();
                    let connection = remote.connect(gix::remote::Direction::Fetch)?;
                    let mut authenticate = connection.configured_credentials(url)?;
                    let connection = connection.with_credentials(
                        move |action: gix::protocol::credentials::helper::Action| {
                            if let Some(url) = action
                                .context()
                                .and_then(|gctx| gctx.url.as_ref().filter(|url| *url != remote_url))
                            {
                                url_for_authentication(url.as_ref());
                            }
                            authenticate(action)
                        },
                    );
                    let outcome = connection
                        .prepare_fetch(&mut progress, gix::remote::ref_map::Options::default())?
                        .with_shallow(shallow.clone())
                        .receive(&mut progress, should_interrupt)?;
                    Ok(outcome)
                });
                let err = match res {
                    Ok(_) => break,
                    Err(e) => e,
                };
                debug!("fetch failed: {}", err);

                if !repo_reinitialized.load(Ordering::Relaxed)
                        // We check for errors that could occur if the configuration, refs or odb files are corrupted.
                        // We don't check for errors related to writing as `gitoxide` is expected to create missing leading
                        // folder before writing files into it, or else not even open a directory as git repository (which is
                        // also handled here).
                        && err.is_corrupted()
                    || has_shallow_lock_file(&err)
                {
                    repo_reinitialized.store(true, Ordering::Relaxed);
                    debug!(
                        "looks like this is a corrupt repository, reinitializing \
                     and trying again"
                    );
                    if oxide::reinitialize(repo_path).is_ok() {
                        continue;
                    }
                }

                return Err(err.into());
            }
            Ok(())
        },
    );
    if repo_reinitialized.load(Ordering::Relaxed) {
        *git2_repo = git2::Repository::open(git2_repo.path())?;
    }
    res
}

fn fetch_with_libgit2(
    repo: &mut git2::Repository,
    remote_url: &str,
    refspecs: Vec<String>,
    tags: bool,
    shallow: gix::remote::fetch::Shallow,
    gctx: &GlobalContext,
) -> CargoResult<()> {
    debug!(target: "git-fetch", backend = "libgit2");

    let git_config = git2::Config::open_default()?;
    with_fetch_options(&git_config, remote_url, gctx, &mut |mut opts| {
        if tags {
            opts.download_tags(git2::AutotagOption::All);
        }
        if let gix::remote::fetch::Shallow::DepthAtRemote(depth) = shallow {
            opts.depth(0i32.saturating_add_unsigned(depth.get()));
        }
        // The `fetch` operation here may fail spuriously due to a corrupt
        // repository. It could also fail, however, for a whole slew of other
        // reasons (aka network related reasons). We want Cargo to automatically
        // recover from corrupt repositories, but we don't want Cargo to stomp
        // over other legitimate errors.
        //
        // Consequently we save off the error of the `fetch` operation and if it
        // looks like a "corrupt repo" error then we blow away the repo and try
        // again. If it looks like any other kind of error, or if we've already
        // blown away the repository, then we want to return the error as-is.
        let mut repo_reinitialized = false;
        loop {
            debug!("initiating fetch of {refspecs:?} from {remote_url}");
            let res = repo
                .remote_anonymous(remote_url)?
                .fetch(&refspecs, Some(&mut opts), None);
            let err = match res {
                Ok(()) => break,
                Err(e) => e,
            };
            debug!("fetch failed: {}", err);

            if !repo_reinitialized && matches!(err.class(), ErrorClass::Reference | ErrorClass::Odb)
            {
                repo_reinitialized = true;
                debug!(
                    "looks like this is a corrupt repository, reinitializing \
                     and trying again"
                );
                if reinitialize(repo).is_ok() {
                    continue;
                }
            }

            return Err(err.into());
        }
        Ok(())
    })
}

/// Attempts to `git gc` a repository.
///
/// Cargo has a bunch of long-lived git repositories in its global cache and
/// some, like the index, are updated very frequently. Right now each update
/// creates a new "pack file" inside the git database, and over time this can
/// cause bad performance and bad current behavior in libgit2.
///
/// One pathological use case today is where libgit2 opens hundreds of file
/// descriptors, getting us dangerously close to blowing out the OS limits of
/// how many fds we can have open. This is detailed in [#4403].
///
/// Instead of trying to be clever about when gc is needed, we just run
/// `git gc --auto` and let git figure it out. It checks its own thresholds
/// (gc.auto, gc.autoPackLimit) and either does the work or exits quickly.
/// If git isn't installed, no worries - we skip it.
///
/// [#4403]: https://github.com/rust-lang/cargo/issues/4403
fn maybe_gc_repo(repo: &mut git2::Repository, gctx: &GlobalContext) -> CargoResult<()> {
    // Let git decide whether gc is actually needed based on its own thresholds
    // (gc.auto, gc.autoPackLimit). This avoids duplicating git's internal logic
    // for deciding when housekeeping is needed.
    //
    // For testing purposes, __CARGO_PACKFILE_LIMIT can be set to override
    // gc.autoPackLimit, which has the same meaning. This lets tests force gc
    // to run by setting a low threshold without depending on git's defaults.
    let mut cmd = Command::new("git");
    if let Ok(limit) = gctx.get_env("__CARGO_PACKFILE_LIMIT") {
        cmd.arg(format!("-c gc.autoPackLimit={}", limit));
    }
    cmd.arg("gc").arg("--auto").current_dir(repo.path());

    match cmd.output() {
        Ok(out) => {
            debug!(
                "git-gc --auto status: {}\n\nstdout ---\n{}\nstderr ---\n{}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            if out.status.success() {
                let new = git2::Repository::open(repo.path())?;
                *repo = new;
                return Ok(());
            }
        }
        Err(e) => debug!("git-gc --auto failed to spawn: {}", e),
    }

    // Alright all else failed, let's start over.
    reinitialize(repo)
}

/// Removes temporary files left from previous activity.
///
/// If libgit2 is interrupted while indexing pack files, it will leave behind
/// some temporary files that it doesn't clean up. These can be quite large in
/// size, so this tries to clean things up.
///
/// This intentionally ignores errors. This is only an opportunistic cleaning,
/// and we don't really care if there are issues (there's unlikely anything
/// that can be done).
///
/// The git CLI has similar behavior (its temp files look like
/// `objects/pack/tmp_pack_9kUSA8`). Those files are normally deleted via `git
/// prune` which is run by `git gc`. However, it doesn't know about libgit2's
/// filenames, so they never get cleaned up.
fn clean_repo_temp_files(repo: &git2::Repository) {
    let path = repo.path().join("objects/pack/pack_git2_*");
    let Some(pattern) = path.to_str() else {
        tracing::warn!("cannot convert {path:?} to a string");
        return;
    };
    let Ok(paths) = glob::glob(pattern) else {
        return;
    };
    for path in paths {
        if let Ok(path) = path {
            match paths::remove_file(&path) {
                Ok(_) => tracing::debug!("removed stale temp git file {path:?}"),
                Err(e) => {
                    tracing::warn!("failed to remove {path:?} while cleaning temp files: {e}")
                }
            }
        }
    }
}

/// Reinitializes a given Git repository. This is useful when a Git repository
/// seems corrupted and we want to start over.
fn reinitialize(repo: &mut git2::Repository) -> CargoResult<()> {
    // Here we want to drop the current repository object pointed to by `repo`,
    // so we initialize temporary repository in a sub-folder, blow away the
    // existing git folder, and then recreate the git repo. Finally we blow away
    // the `tmp` folder we allocated.
    let path = repo.path().to_path_buf();
    debug!("reinitializing git repo at {:?}", path);
    let tmp = path.join("tmp");
    let bare = !repo.path().ends_with(".git");
    *repo = init(&tmp, false)?;
    for entry in path.read_dir()? {
        let entry = entry?;
        if entry.file_name().to_str() == Some("tmp") {
            continue;
        }
        let path = entry.path();
        drop(paths::remove_file(&path).or_else(|_| paths::remove_dir_all(&path)));
    }
    *repo = init(&path, bare)?;
    paths::remove_dir_all(&tmp)?;
    Ok(())
}

/// Initializes a Git repository at `path`.
fn init(path: &Path, bare: bool) -> CargoResult<git2::Repository> {
    let mut opts = git2::RepositoryInitOptions::new();
    // Skip anything related to templates, they just call all sorts of issues as
    // we really don't want to use them yet they insist on being used. See #6240
    // for an example issue that comes up.
    opts.external_template(false);
    opts.bare(bare);
    Ok(git2::Repository::init_opts(&path, &opts)?)
}

/// The result of GitHub fast path check. See [`github_fast_path`] for more.
enum FastPathRev {
    /// The local rev (determined by `reference.resolve(repo)`) is already up to
    /// date with what this rev resolves to on GitHub's server.
    UpToDate,
    /// The following SHA must be fetched in order for the local rev to become
    /// up to date.
    NeedsFetch(Oid),
    /// Don't know whether local rev is up to date. We'll fetch _all_ branches
    /// and tags from the server and see what happens.
    Indeterminate,
}

/// Attempts GitHub's special fast path for testing if we've already got an
/// up-to-date copy of the repository.
///
/// Updating the index is done pretty regularly so we want it to be as fast as
/// possible. For registries hosted on GitHub (like the crates.io index) there's
/// a fast path available to use[^1] to tell us that there's no updates to be
/// made.
///
/// Note that this function should never cause an actual failure because it's
/// just a fast path. As a result, a caller should ignore `Err` returned from
/// this function and move forward on the normal path.
///
/// [^1]: <https://developer.github.com/v3/repos/commits/#get-the-sha-1-of-a-commit-reference>
fn github_fast_path(
    repo: &mut git2::Repository,
    url: &str,
    reference: &GitReference,
    gctx: &GlobalContext,
) -> CargoResult<FastPathRev> {
    let url = Url::parse(url)?;
    if !is_github(&url) {
        return Ok(FastPathRev::Indeterminate);
    }

    let local_object = resolve_ref(reference, repo).ok();

    let github_branch_name = match reference {
        GitReference::Branch(branch) => branch,
        GitReference::Tag(tag) => tag,
        GitReference::DefaultBranch => "HEAD",
        GitReference::Rev(rev) => {
            if rev.starts_with("refs/") {
                rev
            } else if looks_like_commit_hash(rev) {
                // `revparse_single` (used by `resolve`) is the only way to turn
                // short hash -> long hash, but it also parses other things,
                // like branch and tag names, which might coincidentally be
                // valid hex.
                //
                // We only return early if `rev` is a prefix of the object found
                // by `revparse_single`. Don't bother talking to GitHub in that
                // case, since commit hashes are permanent. If a commit with the
                // requested hash is already present in the local clone, its
                // contents must be the same as what is on the server for that
                // hash.
                //
                // If `rev` is not found locally by `revparse_single`, we'll
                // need GitHub to resolve it and get a hash. If `rev` is found
                // but is not a short hash of the found object, it's probably a
                // branch and we also need to get a hash from GitHub, in case
                // the branch has moved.
                if let Some(local_object) = local_object {
                    if is_short_hash_of(rev, local_object) {
                        debug!("github fast path already has {local_object}");
                        return Ok(FastPathRev::UpToDate);
                    }
                }
                // If `rev` is a full commit hash, the only thing it can resolve
                // to is itself. Don't bother talking to GitHub in that case
                // either. (This ensures that we always attempt to fetch the
                // commit directly even if we can't reach the GitHub API.)
                if let Some(oid) = rev_to_oid(rev) {
                    debug!("github fast path is already a full commit hash {rev}");
                    return Ok(FastPathRev::NeedsFetch(oid));
                }
                rev
            } else {
                debug!("can't use github fast path with `rev = \"{}\"`", rev);
                return Ok(FastPathRev::Indeterminate);
            }
        }
    };

    // This expects GitHub urls in the form `github.com/user/repo` and nothing
    // else
    let mut pieces = url
        .path_segments()
        .ok_or_else(|| anyhow!("no path segments on url"))?;
    let username = pieces
        .next()
        .ok_or_else(|| anyhow!("couldn't find username"))?;
    let repository = pieces
        .next()
        .ok_or_else(|| anyhow!("couldn't find repository name"))?;
    if pieces.next().is_some() {
        anyhow::bail!("too many segments on URL");
    }

    // Trim off the `.git` from the repository, if present, since that's
    // optional for GitHub and won't work when we try to use the API as well.
    let repository = repository.strip_suffix(".git").unwrap_or(repository);

    let url = format!(
        "https://api.github.com/repos/{}/{}/commits/{}",
        username, repository, github_branch_name,
    );
    debug!("attempting GitHub fast path for {}", url);
    let mut request =
        Request::get(url).header(http::header::ACCEPT, "application/vnd.github.3.sha");
    if let Some(local_object) = local_object {
        request = request.header(http::header::IF_NONE_MATCH, &format!("\"{local_object}\""));
    }
    let response = gctx
        .http_async()?
        .request_blocking(request.body(Vec::new())?)?;
    let response_code = response.status();
    if response_code == StatusCode::NOT_MODIFIED {
        debug!("github fast path up-to-date");
        Ok(FastPathRev::UpToDate)
    } else if response_code == StatusCode::OK
        && let Some(oid_to_fetch) = rev_to_oid(str::from_utf8(&response.body())?)
    {
        // response expected to be a full hash hexstring (40 or 64 chars)
        debug!("github fast path fetch {oid_to_fetch}");
        Ok(FastPathRev::NeedsFetch(oid_to_fetch))
    } else {
        // Usually response_code == 404 if the repository does not exist, and
        // response_code == 422 if exists but GitHub is unable to resolve the
        // requested rev.
        debug!("github fast path bad response code {response_code}");
        Ok(FastPathRev::Indeterminate)
    }
}

/// Whether a `url` is one from GitHub.
fn is_github(url: &Url) -> bool {
    url.host_str() == Some("github.com")
}

// Give some messages on GitHub PR URL given as is
pub(crate) fn note_github_pull_request(url: &str) -> Option<String> {
    if let Ok(url) = url.parse::<Url>()
        && is_github(&url)
    {
        let path_segments = url
            .path_segments()
            .map(|p| p.into_iter().collect::<Vec<_>>())
            .unwrap_or_default();
        if let [owner, repo, "pull", pr_number, ..] = path_segments[..] {
            let repo_url = format!("https://github.com/{owner}/{repo}.git");
            let rev = format!("refs/pull/{pr_number}/head");
            return Some(format!(
                concat!(
                    "\n\nnote: GitHub url {} is not a repository. \n",
                    "help: Replace the dependency with \n",
                    "       `git = \"{}\" rev = \"{}\"` \n",
                    "   to specify pull requests as dependencies' revision."
                ),
                url, repo_url, rev
            ));
        }
    }

    None
}

/// Whether a `rev` looks like a commit hash (ASCII hex digits).
fn looks_like_commit_hash(rev: &str) -> bool {
    rev.len() >= 7 && rev.chars().all(|ch| ch.is_ascii_hexdigit())
}

/// Whether `rev` is a shorter hash of `oid`.
fn is_short_hash_of(rev: &str, oid: Oid) -> bool {
    let long_hash = oid.to_string();
    match long_hash.get(..rev.len()) {
        Some(truncated_long_hash) => truncated_long_hash.eq_ignore_ascii_case(rev),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_fast_path_full_hash_returns_needs_fetch() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let mut repo = git2::Repository::init_bare(temp_dir.path()).unwrap();
        let full_hash = "c9040898c9183ddbb9402dcbf749ed06d6ea90ad";
        let reference = GitReference::Rev(full_hash.to_string());
        let gctx = GlobalContext::default().unwrap();
        let expected_oid = rev_to_oid(full_hash).unwrap();

        let result =
            github_fast_path(&mut repo, "https://github.com/user/repo", &reference, &gctx).unwrap();

        assert!(matches!(result, FastPathRev::NeedsFetch(oid) if oid == expected_oid));
    }
}

/// Turns a full commit hash revision into an oid.
///
/// Git object ID is supposed to be a hex string of 20 (SHA1) or 32 (SHA256) bytes.
/// Its length must be double to the underlying bytes (40 or 64),
/// otherwise libgit2 would happily zero-pad the returned oid.
///
/// See:
///
/// * <https://github.com/rust-lang/cargo/issues/13188>
/// * <https://github.com/rust-lang/cargo/issues/13968>
pub(super) fn rev_to_oid(rev: &str) -> Option<Oid> {
    Oid::from_str(rev)
        .ok()
        .filter(|oid| oid.as_bytes().len() * 2 == rev.len())
}
