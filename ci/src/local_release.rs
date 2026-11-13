//! The mock GitHub the release flow runs against (stow#1514).
//!
//! `scripts/release-flow-e2e.sh` drives `scripts/release-pr.sh`,
//! `scripts/release-resolve.sh` and `release-plz` against this surface the
//! way the release workflows drive them against github.com: the same
//! endpoints, under `/api/v3/` and `/api/graphql` as release-plz addresses
//! a GitHub Enterprise host (an `http://` repository URL that is not
//! github.com), the same JSON shapes for the fields those three read, and a
//! bare git repository per `owner/repo` under the root named by
//! `STOW_MOCK_GIT_ROOT` as the object store behind them.
//!
//! What it implements is what the flow calls and nothing else: pull
//! requests (list, open, edit, commits, merge), the commits-to-pulls
//! association, commit statuses, branch and tag refs, annotated tags, and
//! the `createCommitOnBranch` GraphQL mutation release-plz commits its
//! release branch with. A caller authenticates with `mock-token:<login>`,
//! and that login is the actor the record carries (a PR's author, a status's
//! creator), which is what `release-resolve.sh` tells the App's PR and the
//! release gate's own status apart by. Merging a pull request is
//! merge-commit only, as `main`'s ruleset allows.

use std::convert::Infallible;
use std::fmt::Write as _;
use std::future::{Future, ready};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Mutex;

use base64::Engine as _;
use futures_lite::io::AsyncWriteExt as _;
use serde::Deserialize;
use serde_json::{Value, json};
use skyzen::extract::{Extractor, Query};
use skyzen::routing::{CreateRouteNode, Params, Route};
use skyzen::utils::{Json, State};
use skyzen::{Request, Response, StatusCode};

use crate::local_server::{LocalServerState, json_response};

/// The prefix of an `Authorization` credential the mock accepts; the rest is
/// the login the request acts as.
const TOKEN_PREFIX: &str = "mock-token:";

/// The all-zero object id: `git update-ref`'s "the ref must not exist".
const ZERO_OID: &str = "0000000000000000000000000000000000000000";

/// The repositories behind the mock and the records GitHub keeps about them
/// that git does not.
#[derive(Debug)]
pub struct ReleaseForge {
    /// Holds `<owner>/<repo>.git`, one bare repository each.
    root: PathBuf,
    pulls: Mutex<Vec<PullRecord>>,
    statuses: Mutex<Vec<StatusRecord>>,
}

impl ReleaseForge {
    /// A forge over the bare repositories under `root`.
    pub const fn new(root: PathBuf) -> Self {
        Self {
            root,
            pulls: Mutex::new(Vec::new()),
            statuses: Mutex::new(Vec::new()),
        }
    }
}

#[derive(Debug, Clone)]
struct PullRecord {
    owner: String,
    repo: String,
    number: u64,
    title: String,
    body: Option<String>,
    open: bool,
    draft: bool,
    head_ref: String,
    base_ref: String,
    labels: Vec<String>,
    author: String,
    created_at: String,
    merged: Option<MergeRecord>,
}

/// What a merge fixes: GitHub keeps the head the PR merged with after the
/// branch moves or goes.
#[derive(Debug, Clone)]
struct MergeRecord {
    head_sha: String,
    base_sha: String,
    merge_commit_sha: String,
    at: String,
}

#[derive(Debug, Clone)]
struct StatusRecord {
    owner: String,
    repo: String,
    id: u64,
    sha: String,
    state: String,
    context: String,
    description: Option<String>,
    target_url: Option<String>,
    creator: String,
    created_at: String,
}

/// An error answered in GitHub's `{"message": …}` envelope.
#[derive(Debug)]
struct ApiError(StatusCode, String);

impl ApiError {
    fn not_found() -> Self {
        Self(StatusCode::NOT_FOUND, "Not Found".to_owned())
    }

    fn unprocessable(message: impl Into<String>) -> Self {
        Self(StatusCode::UNPROCESSABLE_ENTITY, message.into())
    }

    fn internal(message: impl Into<String>) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, message.into())
    }
}

type ApiResult = Result<(StatusCode, Value), ApiError>;

fn respond(result: ApiResult) -> Response {
    match result {
        Ok((status, body)) => json_response(&body, status),
        Err(ApiError(status, message)) => json_response(&json!({ "message": message }), status),
    }
}

/// The login a request authenticates as, from its `Authorization` header.
#[derive(Debug, Clone)]
pub struct Actor(Option<String>);

impl Extractor for Actor {
    type Error = Infallible;

    fn extract(request: &mut Request) -> impl Future<Output = Result<Self, Infallible>> + Send {
        let login = request
            .headers()
            .get(skyzen::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.rsplit_once(char::is_whitespace))
            .and_then(|(_scheme, token)| token.strip_prefix(TOKEN_PREFIX))
            .map(str::to_owned);
        ready(Ok(Self(login)))
    }
}

/// One request's repository and caller.
struct Call<'a> {
    forge: &'a ReleaseForge,
    owner: String,
    repo: String,
    dir: PathBuf,
    actor: String,
    listen: std::net::SocketAddr,
}

impl<'a> Call<'a> {
    fn new(state: &'a LocalServerState, params: &Params, actor: &Actor) -> Result<Self, ApiError> {
        let name = |key: &str| params.get(key).ok().map(str::to_owned);
        let (Some(owner), Some(repo)) = (name("owner"), name("repo")) else {
            return Err(ApiError::not_found());
        };
        Self::open(state, owner, repo, actor)
    }

    fn open(
        state: &'a LocalServerState,
        owner: String,
        repo: String,
        actor: &Actor,
    ) -> Result<Self, ApiError> {
        let forge = state.release.as_deref().ok_or_else(ApiError::not_found)?;
        let login = actor.0.clone().ok_or_else(|| {
            ApiError(
                StatusCode::UNAUTHORIZED,
                format!("Requires authentication: send `Bearer {TOKEN_PREFIX}<login>`"),
            )
        })?;
        if [&owner, &repo]
            .iter()
            .any(|name| name.is_empty() || name.contains(".."))
        {
            return Err(ApiError::not_found());
        }
        let dir = forge.root.join(&owner).join(format!("{repo}.git"));
        if !dir.join("HEAD").is_file() {
            return Err(ApiError::not_found());
        }
        Ok(Self {
            forge,
            owner,
            repo,
            dir,
            actor: login,
            listen: state.listen,
        })
    }

    /// Runs `git` in the bare repository; `stdin` is fed to it.
    async fn run(
        &self,
        args: &[&str],
        stdin: Option<Vec<u8>>,
        env: &[(&str, &str)],
    ) -> Result<std::process::Output, ApiError> {
        let mut command = async_process::Command::new("git");
        command
            .arg("-C")
            .arg(&self.dir)
            .args(args)
            .envs(env.iter().copied())
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| ApiError::internal(format!("spawn git: {error}")))?;
        if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
            pipe.write_all(&bytes)
                .await
                .map_err(|error| ApiError::internal(format!("feed git: {error}")))?;
        }
        child
            .output()
            .await
            .map_err(|error| ApiError::internal(format!("run git: {error}")))
    }

    /// Runs `git` and returns its trimmed stdout; a failure is a 422 carrying
    /// git's own message.
    async fn git(&self, args: &[&str]) -> Result<String, ApiError> {
        self.git_with(args, None, &[]).await
    }

    async fn git_with(
        &self,
        args: &[&str],
        stdin: Option<Vec<u8>>,
        env: &[(&str, &str)],
    ) -> Result<String, ApiError> {
        let output = self.run(args, stdin, env).await?;
        if !output.status.success() {
            return Err(ApiError::unprocessable(format!(
                "git {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    /// The commit a revision names, or `None`.
    async fn commit_of(&self, rev: &str) -> Result<Option<String>, ApiError> {
        if rev.starts_with('-') {
            return Ok(None);
        }
        let output = self
            .run(
                &[
                    "rev-parse",
                    "--verify",
                    "--quiet",
                    &format!("{rev}^{{commit}}"),
                ],
                None,
                &[],
            )
            .await?;
        Ok(output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned()))
    }

    async fn require_commit(&self, rev: &str) -> Result<String, ApiError> {
        self.commit_of(rev)
            .await?
            .ok_or_else(|| ApiError::unprocessable(format!("No commit found for SHA: {rev}")))
    }

    async fn branch_head(&self, branch: &str) -> Result<Option<String>, ApiError> {
        self.commit_of(&format!("refs/heads/{branch}")).await
    }

    /// The identity a commit this call creates carries.
    fn identity(&self) -> [(&'static str, String); 6] {
        let email = format!("{}@users.noreply.github.localhost", self.actor);
        [
            ("GIT_AUTHOR_NAME", self.actor.clone()),
            ("GIT_AUTHOR_EMAIL", email.clone()),
            ("GIT_COMMITTER_NAME", self.actor.clone()),
            ("GIT_COMMITTER_EMAIL", email),
            ("GIT_AUTHOR_DATE", now_rfc3339()),
            ("GIT_COMMITTER_DATE", now_rfc3339()),
        ]
    }

    async fn git_as_actor(
        &self,
        args: &[&str],
        stdin: Option<Vec<u8>>,
        extra: &[(&str, &str)],
    ) -> Result<String, ApiError> {
        let identity = self.identity();
        let mut env: Vec<(&str, &str)> = identity.iter().map(|(k, v)| (*k, v.as_str())).collect();
        env.extend_from_slice(extra);
        self.git_with(args, stdin, &env).await
    }

    fn html_url(&self, tail: &str) -> String {
        format!("http://{}/{}/{}/{tail}", self.listen, self.owner, self.repo)
    }

    fn pulls(&self) -> Vec<PullRecord> {
        self.forge
            .pulls
            .lock()
            .expect("pulls mutex poisoned")
            .iter()
            .filter(|pull| pull.owner == self.owner && pull.repo == self.repo)
            .cloned()
            .collect()
    }

    fn pull(&self, number: &str) -> Result<PullRecord, ApiError> {
        let number: u64 = number.parse().map_err(|_| ApiError::not_found())?;
        self.pulls()
            .into_iter()
            .find(|pull| pull.number == number)
            .ok_or_else(ApiError::not_found)
    }

    fn update_pull(&self, number: u64, edit: impl FnOnce(&mut PullRecord)) {
        let mut pulls = self.forge.pulls.lock().expect("pulls mutex poisoned");
        let pull = pulls
            .iter_mut()
            .find(|pull| {
                pull.owner == self.owner && pull.repo == self.repo && pull.number == number
            })
            .expect("pull recorded");
        edit(pull);
        drop(pulls);
    }

    /// The PR's head: where its branch is now, or where it merged.
    async fn pull_head(&self, pull: &PullRecord) -> Result<String, ApiError> {
        match &pull.merged {
            Some(merged) => Ok(merged.head_sha.clone()),
            None => self.branch_head(&pull.head_ref).await?.ok_or_else(|| {
                ApiError::unprocessable(format!("branch {} is gone", pull.head_ref))
            }),
        }
    }

    async fn pull_json(&self, pull: &PullRecord) -> Result<Value, ApiError> {
        let head_sha = self.pull_head(pull).await?;
        let base_sha = match &pull.merged {
            Some(merged) => Some(merged.base_sha.clone()),
            None => self.branch_head(&pull.base_ref).await?,
        };
        Ok(json!({
            "number": pull.number,
            "html_url": self.html_url(&format!("pull/{}", pull.number)),
            "state": if pull.open { "open" } else { "closed" },
            "title": pull.title,
            "body": pull.body,
            "draft": pull.draft,
            "user": {"id": 1, "login": pull.author},
            "head": {"ref": pull.head_ref, "sha": head_sha},
            "base": {"ref": pull.base_ref, "sha": base_sha},
            "labels": pull.labels.iter().enumerate()
                .map(|(id, name)| json!({"id": id + 1, "name": name}))
                .collect::<Vec<_>>(),
            "created_at": pull.created_at,
            "merged_at": pull.merged.as_ref().map(|merged| merged.at.clone()),
            "merge_commit_sha": pull.merged.as_ref().map(|merged| merged.merge_commit_sha.clone()),
        }))
    }

    async fn pulls_json(&self, pulls: &[PullRecord]) -> Result<Value, ApiError> {
        let mut rows = Vec::with_capacity(pulls.len());
        for pull in pulls {
            rows.push(self.pull_json(pull).await?);
        }
        Ok(Value::Array(rows))
    }
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("a UTC timestamp formats")
}

/// `page`/`per_page` as GitHub reads them: 30 rows a page by default.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct PageQuery {
    state: Option<String>,
    page: Option<usize>,
    per_page: Option<usize>,
}

impl PageQuery {
    fn window<T: Clone>(&self, rows: &[T]) -> Vec<T> {
        let per_page = self.per_page.unwrap_or(30).clamp(1, 100);
        let page = self.page.unwrap_or(1).max(1);
        rows.iter()
            .skip((page - 1) * per_page)
            .take(per_page)
            .cloned()
            .collect()
    }
}

/// The REST routes, mounted under `/api/v3`.
pub fn routes() -> Route {
    Route::new((
        "/repos/{owner}/{repo}/pulls"
            .at(list_pulls)
            .post(create_pull),
        "/repos/{owner}/{repo}/pulls/{number}"
            .at(get_pull)
            .patch(edit_pull),
        "/repos/{owner}/{repo}/pulls/{number}/commits".at(pull_commits),
        "/repos/{owner}/{repo}/pulls/{number}/merge".put(merge_pull),
        "/repos/{owner}/{repo}/issues/{number}/labels".post(add_labels),
        "/repos/{owner}/{repo}/commits/{sha}".at(get_commit),
        "/repos/{owner}/{repo}/commits/{sha}/pulls".at(commit_pulls),
        "/repos/{owner}/{repo}/commits/{sha}/statuses".at(list_statuses),
        "/repos/{owner}/{repo}/statuses/{sha}".post(create_status),
        "/repos/{owner}/{repo}/git/refs".post(create_ref),
        "/repos/{owner}/{repo}/git/refs/heads/{branch}"
            .patch(update_branch)
            .delete(delete_branch),
        "/repos/{owner}/{repo}/git/tags".post(create_tag),
    ))
}

// ---------------------------------------------------------------------------
// Pull requests
// ---------------------------------------------------------------------------

async fn list_pulls(
    State(state): State<LocalServerState>,
    params: Params,
    actor: Actor,
    Query(query): Query<PageQuery>,
) -> Response {
    respond(
        async {
            let call = Call::new(&state, &params, &actor)?;
            let want = query.state.as_deref().unwrap_or("open");
            let mut pulls: Vec<PullRecord> = call
                .pulls()
                .into_iter()
                .filter(|pull| match want {
                    "all" => true,
                    "closed" => !pull.open,
                    _ => pull.open,
                })
                .collect();
            pulls.reverse();
            let page = query.window(&pulls);
            Ok((StatusCode::OK, call.pulls_json(&page).await?))
        }
        .await,
    )
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct NewPull {
    title: String,
    body: Option<String>,
    base: String,
    head: String,
    #[serde(default)]
    draft: bool,
}

async fn create_pull(
    State(state): State<LocalServerState>,
    params: Params,
    actor: Actor,
    Json(new): Json<NewPull>,
) -> Response {
    respond(
        async {
            let call = Call::new(&state, &params, &actor)?;
            for branch in [&new.base, &new.head] {
                if call.branch_head(branch).await?.is_none() {
                    return Err(ApiError::unprocessable(format!(
                        "branch {branch} does not exist"
                    )));
                }
            }
            let pull = {
                let mut pulls = call.forge.pulls.lock().expect("pulls mutex poisoned");
                let number = pulls
                    .iter()
                    .filter(|pull| pull.owner == call.owner && pull.repo == call.repo)
                    .count() as u64
                    + 1;
                let pull = PullRecord {
                    owner: call.owner.clone(),
                    repo: call.repo.clone(),
                    number,
                    title: new.title,
                    body: new.body,
                    open: true,
                    draft: new.draft,
                    head_ref: new.head,
                    base_ref: new.base,
                    labels: Vec::new(),
                    author: call.actor.clone(),
                    created_at: now_rfc3339(),
                    merged: None,
                };
                pulls.push(pull.clone());
                pull
            };
            Ok((StatusCode::CREATED, call.pull_json(&pull).await?))
        }
        .await,
    )
}

async fn get_pull(State(state): State<LocalServerState>, params: Params, actor: Actor) -> Response {
    respond(
        async {
            let call = Call::new(&state, &params, &actor)?;
            let pull = call.pull(params.get("number").unwrap_or_default())?;
            Ok((StatusCode::OK, call.pull_json(&pull).await?))
        }
        .await,
    )
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct PullEdit {
    title: Option<String>,
    body: Option<String>,
    state: Option<String>,
}

async fn edit_pull(
    State(state): State<LocalServerState>,
    params: Params,
    actor: Actor,
    Json(edit): Json<PullEdit>,
) -> Response {
    respond(
        async {
            let call = Call::new(&state, &params, &actor)?;
            let pull = call.pull(params.get("number").unwrap_or_default())?;
            let open = match edit.state.as_deref() {
                None => None,
                Some("open") => Some(true),
                Some("closed") => Some(false),
                Some(other) => {
                    return Err(ApiError::unprocessable(format!(
                        "state `{other}` is not open or closed"
                    )));
                }
            };
            call.update_pull(pull.number, |pull| {
                if let Some(title) = edit.title {
                    pull.title = title;
                }
                if let Some(body) = edit.body {
                    pull.body = Some(body);
                }
                if let Some(open) = open {
                    pull.open = open;
                }
            });
            let pull = call.pull(&pull.number.to_string())?;
            Ok((StatusCode::OK, call.pull_json(&pull).await?))
        }
        .await,
    )
}

/// The PR's commits, oldest first: those its head has beyond its base.
async fn pull_commits(
    State(state): State<LocalServerState>,
    params: Params,
    actor: Actor,
) -> Response {
    respond(
        async {
            let call = Call::new(&state, &params, &actor)?;
            let pull = call.pull(params.get("number").unwrap_or_default())?;
            let head = call.pull_head(&pull).await?;
            let base = match &pull.merged {
                Some(merged) => merged.base_sha.clone(),
                None => {
                    call.require_commit(&format!("refs/heads/{}", pull.base_ref))
                        .await?
                }
            };
            let listed = call
                .git(&["rev-list", "--reverse", &head, "--not", &base])
                .await?;
            let mut commits = Vec::new();
            for sha in listed.lines() {
                let login = call.git(&["log", "-1", "--format=%an", sha]).await?;
                commits.push(json!({"sha": sha, "author": {"id": 1, "login": login}}));
            }
            Ok((StatusCode::OK, Value::Array(commits)))
        }
        .await,
    )
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct MergeRequest {
    merge_method: Option<String>,
}

/// Merges the PR into its base as a merge commit — the only method `main`
/// allows.
async fn merge_pull(
    State(state): State<LocalServerState>,
    params: Params,
    actor: Actor,
    Json(request): Json<MergeRequest>,
) -> Response {
    respond(
        async {
            let call = Call::new(&state, &params, &actor)?;
            let pull = call.pull(params.get("number").unwrap_or_default())?;
            if !pull.open || pull.merged.is_some() {
                return Err(ApiError(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "Pull Request is not mergeable".to_owned(),
                ));
            }
            if let Some(method) = request.merge_method.as_deref().filter(|m| *m != "merge") {
                return Err(ApiError(
                    StatusCode::METHOD_NOT_ALLOWED,
                    format!("{method} merges are not allowed on this repository"),
                ));
            }
            let head = call.pull_head(&pull).await?;
            let base = call.require_commit(&format!("refs/heads/{}", pull.base_ref)).await?;
            let merged = call.run(&["merge-tree", "--write-tree", &base, &head], None, &[]).await?;
            if !merged.status.success() {
                return Err(ApiError(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "Merge conflict".to_owned(),
                ));
            }
            let stdout = String::from_utf8_lossy(&merged.stdout);
            let tree = stdout.lines().next().unwrap_or_default().trim().to_owned();
            let message = format!(
                "Merge pull request #{} from {}/{}\n\n{}",
                pull.number, call.owner, pull.head_ref, pull.title
            );
            let merge_commit = call
                .git_as_actor(
                    &["commit-tree", &tree, "-p", &base, "-p", &head, "-m", &message],
                    None,
                    &[],
                )
                .await?;
            call.git(&[
                "update-ref",
                &format!("refs/heads/{}", pull.base_ref),
                &merge_commit,
                &base,
            ])
            .await?;
            call.update_pull(pull.number, |pull| {
                pull.open = false;
                pull.merged = Some(MergeRecord {
                    head_sha: head,
                    base_sha: base,
                    merge_commit_sha: merge_commit.clone(),
                    at: now_rfc3339(),
                });
            });
            Ok((
                StatusCode::OK,
                json!({"sha": merge_commit, "merged": true, "message": "Pull Request successfully merged"}),
            ))
        }
        .await,
    )
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct Labels {
    labels: Vec<String>,
}

async fn add_labels(
    State(state): State<LocalServerState>,
    params: Params,
    actor: Actor,
    Json(added): Json<Labels>,
) -> Response {
    respond(
        async {
            let call = Call::new(&state, &params, &actor)?;
            let pull = call.pull(params.get("number").unwrap_or_default())?;
            call.update_pull(pull.number, |pull| {
                for label in added.labels {
                    if !pull.labels.contains(&label) {
                        pull.labels.push(label);
                    }
                }
            });
            let pull = call.pull(&pull.number.to_string())?;
            let labels: Vec<Value> = pull
                .labels
                .iter()
                .enumerate()
                .map(|(id, name)| json!({"id": id + 1, "name": name}))
                .collect();
            Ok((StatusCode::OK, Value::Array(labels)))
        }
        .await,
    )
}

// ---------------------------------------------------------------------------
// Commits and statuses
// ---------------------------------------------------------------------------

async fn get_commit(
    State(state): State<LocalServerState>,
    params: Params,
    actor: Actor,
) -> Response {
    respond(
        async {
            let call = Call::new(&state, &params, &actor)?;
            let sha = call
                .commit_of(params.get("sha").unwrap_or_default())
                .await?
                .ok_or_else(ApiError::not_found)?;
            let login = call.git(&["log", "-1", "--format=%an", &sha]).await?;
            let parents = call.git(&["log", "-1", "--format=%P", &sha]).await?;
            Ok((
                StatusCode::OK,
                json!({
                    "sha": sha,
                    "author": {"id": 1, "login": login},
                    "parents": parents.split_whitespace()
                        .map(|parent| json!({"sha": parent}))
                        .collect::<Vec<_>>(),
                }),
            ))
        }
        .await,
    )
}

/// The PRs a commit belongs to: those whose head it is, or whose merge it is.
async fn commit_pulls(
    State(state): State<LocalServerState>,
    params: Params,
    actor: Actor,
) -> Response {
    respond(
        async {
            let call = Call::new(&state, &params, &actor)?;
            let sha = call
                .commit_of(params.get("sha").unwrap_or_default())
                .await?
                .ok_or_else(ApiError::not_found)?;
            let mut associated = Vec::new();
            for pull in call.pulls() {
                let is_head = call.pull_head(&pull).await.is_ok_and(|head| head == sha);
                let is_merge = pull
                    .merged
                    .as_ref()
                    .is_some_and(|merged| merged.merge_commit_sha == sha);
                if is_head || is_merge {
                    associated.push(pull);
                }
            }
            Ok((StatusCode::OK, call.pulls_json(&associated).await?))
        }
        .await,
    )
}

fn status_json(call: &Call<'_>, status: &StatusRecord) -> Value {
    json!({
        "id": status.id,
        "state": status.state,
        "context": status.context,
        "description": status.description,
        "target_url": status.target_url,
        "created_at": status.created_at,
        "updated_at": status.created_at,
        "creator": {"id": 1, "login": status.creator},
        "url": call.html_url(&format!("statuses/{}", status.sha)),
    })
}

/// The commit's statuses, newest first, paged as GitHub pages them.
async fn list_statuses(
    State(state): State<LocalServerState>,
    params: Params,
    actor: Actor,
    Query(query): Query<PageQuery>,
) -> Response {
    respond(
        async {
            let call = Call::new(&state, &params, &actor)?;
            let sha = call
                .commit_of(params.get("sha").unwrap_or_default())
                .await?
                .ok_or_else(ApiError::not_found)?;
            let mut statuses: Vec<StatusRecord> = call
                .forge
                .statuses
                .lock()
                .expect("statuses mutex poisoned")
                .iter()
                .filter(|status| {
                    status.owner == call.owner && status.repo == call.repo && status.sha == sha
                })
                .cloned()
                .collect();
            statuses.reverse();
            let page = query.window(&statuses);
            Ok((
                StatusCode::OK,
                Value::Array(
                    page.iter()
                        .map(|status| status_json(&call, status))
                        .collect(),
                ),
            ))
        }
        .await,
    )
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct NewStatus {
    state: String,
    context: String,
    description: Option<String>,
    target_url: Option<String>,
}

async fn create_status(
    State(state): State<LocalServerState>,
    params: Params,
    actor: Actor,
    Json(new): Json<NewStatus>,
) -> Response {
    respond(
        async {
            let call = Call::new(&state, &params, &actor)?;
            if !["error", "failure", "pending", "success"].contains(&new.state.as_str()) {
                return Err(ApiError::unprocessable(format!(
                    "state `{}` is not valid",
                    new.state
                )));
            }
            let sha = call
                .require_commit(params.get("sha").unwrap_or_default())
                .await?;
            let mut statuses = call.forge.statuses.lock().expect("statuses mutex poisoned");
            let status = StatusRecord {
                owner: call.owner.clone(),
                repo: call.repo.clone(),
                id: statuses.len() as u64 + 1,
                sha,
                state: new.state,
                context: new.context,
                description: new.description,
                target_url: new.target_url,
                creator: call.actor.clone(),
                created_at: now_rfc3339(),
            };
            let body = status_json(&call, &status);
            statuses.push(status);
            drop(statuses);
            Ok((StatusCode::CREATED, body))
        }
        .await,
    )
}

// ---------------------------------------------------------------------------
// Refs and tags
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct NewRef {
    #[serde(rename = "ref")]
    name: String,
    sha: String,
}

/// An object the repository holds, commit or tag.
async fn require_object(call: &Call<'_>, sha: &str) -> Result<(), ApiError> {
    if sha.starts_with('-')
        || !call
            .run(&["cat-file", "-e", sha], None, &[])
            .await?
            .status
            .success()
    {
        return Err(ApiError::unprocessable(format!(
            "Object does not exist: {sha}"
        )));
    }
    Ok(())
}

async fn create_ref(
    State(state): State<LocalServerState>,
    params: Params,
    actor: Actor,
    Json(new): Json<NewRef>,
) -> Response {
    respond(
        async {
            let call = Call::new(&state, &params, &actor)?;
            if !new.name.starts_with("refs/heads/") && !new.name.starts_with("refs/tags/") {
                return Err(ApiError::unprocessable(format!(
                    "ref `{}` is not a branch or tag",
                    new.name
                )));
            }
            require_object(&call, &new.sha).await?;
            let created = call
                .run(&["update-ref", &new.name, &new.sha, ZERO_OID], None, &[])
                .await?;
            if !created.status.success() {
                return Err(ApiError::unprocessable("Reference already exists"));
            }
            Ok((
                StatusCode::CREATED,
                json!({"ref": new.name, "object": {"sha": new.sha}}),
            ))
        }
        .await,
    )
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct RefUpdate {
    sha: String,
    #[serde(default)]
    force: bool,
}

async fn update_branch(
    State(state): State<LocalServerState>,
    params: Params,
    actor: Actor,
    Json(update): Json<RefUpdate>,
) -> Response {
    respond(
        async {
            let call = Call::new(&state, &params, &actor)?;
            let name = format!("refs/heads/{}", params.get("branch").unwrap_or_default());
            let current = call
                .commit_of(&name)
                .await?
                .ok_or_else(ApiError::not_found)?;
            let target = call.require_commit(&update.sha).await?;
            if !update.force
                && !call
                    .run(
                        &["merge-base", "--is-ancestor", &current, &target],
                        None,
                        &[],
                    )
                    .await?
                    .status
                    .success()
            {
                return Err(ApiError::unprocessable("Update is not a fast forward"));
            }
            call.git(&["update-ref", &name, &target, &current]).await?;
            Ok((
                StatusCode::OK,
                json!({"ref": name, "object": {"sha": target}}),
            ))
        }
        .await,
    )
}

async fn delete_branch(
    State(state): State<LocalServerState>,
    params: Params,
    actor: Actor,
) -> Response {
    respond(
        async {
            let call = Call::new(&state, &params, &actor)?;
            let name = format!("refs/heads/{}", params.get("branch").unwrap_or_default());
            let current = call
                .commit_of(&name)
                .await?
                .ok_or_else(ApiError::not_found)?;
            call.git(&["update-ref", "-d", &name, &current]).await?;
            Ok((StatusCode::NO_CONTENT, Value::Null))
        }
        .await,
    )
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct NewTag {
    tag: String,
    message: String,
    object: String,
    #[serde(rename = "type")]
    kind: String,
}

/// An annotated tag object, which a `refs/tags/…` ref then names.
async fn create_tag(
    State(state): State<LocalServerState>,
    params: Params,
    actor: Actor,
    Json(new): Json<NewTag>,
) -> Response {
    respond(
        async {
            let call = Call::new(&state, &params, &actor)?;
            if new.kind != "commit" {
                return Err(ApiError::unprocessable("only commits are tagged"));
            }
            let object = call.require_commit(&new.object).await?;
            let tagger = format!(
                "{0} <{0}@users.noreply.github.localhost> {1} +0000",
                call.actor,
                time::OffsetDateTime::now_utc().unix_timestamp()
            );
            let tag = format!(
                "object {object}\ntype commit\ntag {}\ntagger {tagger}\n\n{}\n",
                new.tag, new.message
            );
            let sha = call
                .git_with(&["mktag"], Some(tag.into_bytes()), &[])
                .await?;
            Ok((
                StatusCode::CREATED,
                json!({"sha": sha, "tag": new.tag, "object": {"sha": object, "type": "commit"}}),
            ))
        }
        .await,
    )
}

// ---------------------------------------------------------------------------
// GraphQL: createCommitOnBranch
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct GraphqlRequest {
    query: String,
    variables: GraphqlVariables,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct GraphqlVariables {
    input: CommitInput,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct CommitInput {
    branch: CommitBranch,
    message: CommitMessage,
    expected_head_oid: String,
    file_changes: FileChanges,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct CommitBranch {
    repository_name_with_owner: String,
    branch_name: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct CommitMessage {
    headline: String,
    body: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct FileChanges {
    #[serde(default)]
    additions: Vec<Addition>,
    #[serde(default)]
    deletions: Vec<Deletion>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct Addition {
    path: String,
    /// Base64 file contents.
    contents: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct Deletion {
    path: String,
}

/// `POST /api/graphql` — the one mutation release-plz commits with. GraphQL
/// answers 200 with an `errors` array on failure.
pub async fn graphql(
    State(state): State<LocalServerState>,
    actor: Actor,
    Json(request): Json<GraphqlRequest>,
) -> Response {
    let result = async {
        if !request.query.contains("createCommitOnBranch") {
            return Err(ApiError::unprocessable(
                "only createCommitOnBranch is served",
            ));
        }
        let input = request.variables.input;
        let (owner, repo) = input
            .branch
            .repository_name_with_owner
            .split_once('/')
            .ok_or_else(|| ApiError::unprocessable("repositoryNameWithOwner is owner/repo"))?;
        let call = Call::open(&state, owner.to_owned(), repo.to_owned(), &actor)?;
        let commit = commit_on_branch(&call, &input).await?;
        Ok(json!({"data": {"createCommitOnBranch": {"commit": {"oid": commit}}}}))
    }
    .await;
    match result {
        Ok(body) => json_response(&body, StatusCode::OK),
        Err(ApiError(_, message)) => json_response(
            &json!({"errors": [{"type": "UNPROCESSABLE", "message": message}]}),
            StatusCode::OK,
        ),
    }
}

/// Applies the changes to the branch head the caller expected and moves the
/// branch to the new commit — a verified API commit, not a push.
async fn commit_on_branch(call: &Call<'_>, input: &CommitInput) -> Result<String, ApiError> {
    let name = format!("refs/heads/{}", input.branch.branch_name);
    let head = call
        .commit_of(&name)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if head != input.expected_head_oid {
        return Err(ApiError::unprocessable(format!(
            "Expected branch to point to {} but it points to {head}",
            input.expected_head_oid
        )));
    }

    let mut index_info = String::new();
    for addition in &input.file_changes.additions {
        let contents = base64::engine::general_purpose::STANDARD
            .decode(&addition.contents)
            .map_err(|error| ApiError::unprocessable(format!("{}: {error}", addition.path)))?;
        let blob = call
            .git_with(&["hash-object", "-w", "--stdin"], Some(contents), &[])
            .await?;
        let _ = writeln!(index_info, "100644 {blob}\t{}", addition.path);
    }
    for deletion in &input.file_changes.deletions {
        let _ = writeln!(index_info, "0 {ZERO_OID}\t{}", deletion.path);
    }

    let scratch = tempfile::tempdir().map_err(|error| ApiError::internal(error.to_string()))?;
    let index = scratch.path().join("index");
    let index = index.to_string_lossy();
    let env = [("GIT_INDEX_FILE", index.as_ref())];
    call.git_with(&["read-tree", &head], None, &env).await?;
    call.git_with(
        &["update-index", "--index-info"],
        Some(index_info.into_bytes()),
        &env,
    )
    .await?;
    let tree = call.git_with(&["write-tree"], None, &env).await?;

    let mut message = input.message.headline.clone();
    if let Some(body) = &input.message.body {
        message.push_str("\n\n");
        message.push_str(body);
    }
    let commit = call
        .git_as_actor(
            &["commit-tree", &tree, "-p", &head, "-m", &message],
            None,
            &[],
        )
        .await?;
    call.git(&["update-ref", &name, &commit, &head]).await?;
    Ok(commit)
}
