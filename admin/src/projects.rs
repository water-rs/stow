//! `stow-admin preheat projects …` — the stars-ranked preheat lane.
//!
//! `generate` rebuilds `preheat/projects.toml` from GitHub's most-starred
//! Rust repositories: a candidate is admitted when its git tree carries a
//! `Cargo.lock` beside a `Cargo.toml`, shallowest first, and every other
//! candidate is reported with its rejection reason. The list is generated
//! and merged by a human — nothing here is ever queried live during a
//! wave.
//!
//! `submit` turns each listed repository into ordinary crate tasks: the
//! checkout's committed lockfile is deleted so cargo re-resolves to the
//! latest semver-compatible versions, `cargo metadata --filter-platform`
//! runs once per CI target, and every crates.io node in the resolve is
//! enqueued at its resolved feature set with its crates.io dependencies
//! as `depends_on` edges at the same `(target, rustc_version)`. A
//! repository that fails to resolve is reported and skipped — one bad
//! manifest must not sink the wave.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use cargo_metadata::{DependencyKind, Metadata, PackageId, TargetKind};
use clap::{Args, Subcommand};
use stow_types::api::{EnqueueDependency, EnqueueRequest, EnqueueSource, SchedulerSubmitResponse};
use stow_types::identity::{
    CrateName, CrateVersion as TypedCrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
};
use stow_types::stow_error;

use crate::render::{self, Output, Table};
use crate::{Edge, github};

/// `preheat projects` — the stars-ranked lane, two verbs.
#[derive(Debug, Args)]
pub struct ProjectsArgs {
    /// The projects subcommand to run.
    #[command(subcommand)]
    pub command: ProjectsCommand,
}

/// `preheat projects` subcommands.
#[derive(Debug, Subcommand)]
pub enum ProjectsCommand {
    /// Rebuild `preheat/projects.toml` from GitHub's most-starred Rust
    /// repositories. Writes the list and prints a rejection report; the
    /// weekly job that runs this opens the pull request.
    Generate(GenerateArgs),
    /// Resolve every repository `preheat/projects.toml` lists and enqueue
    /// each crates.io package in its resolve graph as an ordinary crate
    /// task, with the graph's crates.io edges as `depends_on`.
    Submit(SubmitArgs),
}

/// `preheat projects generate` arguments.
#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// GitHub search floor — `stars:>N` on `language:rust`, ranked by
    /// stars descending. `--limit` bounds the sweep; the floor only
    /// prunes the tail.
    #[arg(long, default_value_t = 250)]
    pub min_stars: u64,
    /// How many candidates to inspect, most-starred first. GitHub search
    /// pages at 100 and caps a query at 1000 results.
    #[arg(long, default_value_t = 200)]
    pub limit: usize,
    /// File the generated list is written to.
    #[arg(long, default_value = "preheat/projects.toml")]
    pub output: PathBuf,
}

/// `preheat projects submit` arguments.
#[derive(Debug, Args)]
pub struct SubmitArgs {
    /// The reviewed repository list `generate` writes.
    #[arg(long, default_value = "preheat/projects.toml")]
    pub file: PathBuf,
    /// Stable rustc version the tasks build for.
    #[arg(long)]
    pub rustc_version: String,
    /// Comma-separated CI target triples to resolve and enqueue for.
    /// Defaults to every triple `stow_types::api::CI_TARGET_TRIPLES`
    /// covers — the list never grows for one project.
    #[arg(long, value_delimiter = ',')]
    pub targets: Option<Vec<String>>,
    /// Submit the batch. Without it the command prints the plan and exits
    /// 0 without enqueuing.
    #[arg(long)]
    pub yes: bool,
}

/// The schema of `preheat/projects.toml`: a reviewed list of
/// repositories, nothing about commits or task shapes.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectsFile {
    /// One entry per admitted repository, kept in generation order.
    project: Vec<ProjectEntry>,
}

/// One listed repository — its URL, and nothing else.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectEntry {
    /// `https://github.com/<owner>/<name>` — the form `generate` writes.
    repo: String,
}

/// The search page shape `GET /search/repositories` answers with.
#[derive(Debug, serde::Deserialize)]
struct SearchPage {
    /// Candidate repositories, most-starred first.
    items: Vec<SearchItem>,
}

/// One search result — the fields admission needs.
#[derive(Debug, serde::Deserialize)]
struct SearchItem {
    /// `owner/name` the API identifies the repository by.
    full_name: String,
    /// The branch `git trees` lists paths under; absent on empty repos.
    default_branch: Option<String>,
}

/// The `GET /repos/{owner}/{repo}/git/trees/{ref}?recursive=1` response.
#[derive(Debug, serde::Deserialize)]
struct TreeResponse {
    /// Every path the ref's tree carries.
    tree: Vec<TreeEntry>,
    /// True when GitHub clipped the listing — a lockfile may sit beyond
    /// what was returned, so a reject here reports the uncertainty.
    #[serde(default)]
    truncated: bool,
}

/// One tree entry: its path and kind (`blob`, `tree`, `commit`).
#[derive(Debug, serde::Deserialize)]
struct TreeEntry {
    /// Repository-relative path.
    path: String,
    /// The entry kind — only blobs are candidate lockfiles/manifests.
    #[serde(rename = "type")]
    kind: String,
}

/// A repository the sweep refused, with the reason it gave.
#[derive(Debug, serde::Serialize)]
struct Rejection {
    /// `owner/name` as returned by the search.
    repository: String,
    /// Why admission failed — the report a reviewer sees.
    reason: String,
}

/// What `generate` reports: the file it wrote, every admission, and
/// every rejection with its reason.
#[derive(Debug, serde::Serialize)]
struct GenerateReport {
    /// The file the list was written to.
    file: String,
    /// How many candidates the sweep inspected.
    scanned: usize,
    /// Admitted repositories, in list order.
    admitted: Vec<String>,
    /// Rejected candidates with their reasons.
    rejected: Vec<Rejection>,
    /// Candidates the admission rule never evaluated — a transport
    /// failure (an IP-allowlist 403, an unreachable API) answered before
    /// the tree could be read. Distinct from `rejected` so a reader does
    /// not conclude these repositories failed the filter.
    not_evaluated: Vec<Rejection>,
}

/// A listed repository `submit` could not resolve, with its reason.
#[derive(Debug, serde::Serialize)]
struct SkippedRepo {
    /// The repository URL as the file carried it.
    repo: String,
    /// Why resolution failed — clone, manifest, or `cargo metadata`.
    reason: String,
}

/// One repository's contribution to the plan: its task count.
#[derive(Debug, serde::Serialize)]
struct RepoContribution {
    /// The repository URL as the file carried it.
    repo: String,
    /// How many enqueue requests its resolve graphs produced.
    tasks: usize,
}

/// The plan `submit` previews and applies: every task every repository
/// produced, plus per-repository outcomes.
#[derive(Debug, serde::Serialize)]
struct ProjectsPlan {
    /// The repository list the plan was built from.
    file: String,
    /// Every enqueue request across every repository and target —
    /// deduplication is the scheduler's `task_id`, not a pass here.
    tasks: Vec<EnqueueRequest>,
    /// How many requests each listed repository produced.
    per_repo: Vec<RepoContribution>,
    /// Repositories resolution failed on, with their reasons.
    skipped: Vec<SkippedRepo>,
}

/// The aggregated answer of the chunked submits `apply` ran.
#[derive(Debug, serde::Serialize)]
pub struct SubmitOutcome {
    /// How many batches were posted to the scheduler.
    pub batches: usize,
    /// Total requests the edge accepted across batches.
    pub submitted: u32,
    /// Total new tasks inserted across batches.
    pub inserted: u32,
    /// Total requests deduplicated away across batches.
    pub dropped: u32,
}

/// GitHub search pages return at most 100 entries.
const SEARCH_PER_PAGE: usize = 100;
/// The search API refuses to page beyond result 1000.
const SEARCH_HARD_LIMIT: usize = 1000;
/// Requests per `POST /scheduler/tasks/submit` — under the edge's own
/// `MAX_EXPANDED_TASKS` bound so a wave never splits mid-application.
const SUBMIT_CHUNK: usize = 1000;
/// The toolchain project checkouts resolve under — pinned so a
/// repository's `rust-toolchain.toml` cannot rustup-install per repo.
const RESOLVE_TOOLCHAIN: &str = "stable";

/// The header comment `generate` writes above the `[[project]]` rows —
/// the schema's only documentation lives in the file itself.
const PROJECTS_HEADER: &str = "\
# Reviewed GitHub repositories the projects preheat lane resolves into
# crate tasks. For each entry the wave clones the tree, drops the
# committed Cargo.lock, and runs `cargo metadata --filter-platform` once
# per CI target; every crates.io package in the resolve is enqueued at
# its resolved feature set — an ordinary crate task, never a project
# task.
#
# The list is GENERATED, not curated: `stow-admin preheat projects
# generate` rebuilds it from GitHub's most-starred Rust repositories and
# `preheat-projects.yml` opens the pull request. A repository is
# admitted when its git tree holds a Cargo.lock next to the workspace
# manifest; a library commits no lockfile by convention and drops out —
# the download-ranked lane covers those. Review the diff before merging:
# an entry spends runner minutes on every wave.
#
#   [[project]]
#   repo = \"https://github.com/<org>/<repo>\"
#
";

/// Dispatch the projects lane: `generate` needs only GitHub; `submit`
/// resolves locally and posts batches to the edge.
pub async fn run(args: ProjectsArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        ProjectsCommand::Generate(args) => {
            let token = crate::github_token().await?;
            generate(&token, &args, output).await
        }
        ProjectsCommand::Submit(args) => {
            let edge = crate::Edge::connect().await?;
            submit(&edge, &args, output).await
        }
    }
}

/// `preheat projects generate` — search, admit, write the file, report.
async fn generate(
    token: &str,
    args: &GenerateArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    if args.limit == 0 {
        return Err(stow_error!("--limit must be at least 1"));
    }
    if args.limit > SEARCH_HARD_LIMIT {
        return Err(stow_error!(
            "--limit {} exceeds the search API's {SEARCH_HARD_LIMIT}-result ceiling",
            args.limit
        ));
    }
    let candidates = search(token, args.min_stars, args.limit).await?;
    let mut admitted = Vec::with_capacity(candidates.len());
    let mut rejected = Vec::new();
    let mut not_evaluated = Vec::new();
    for candidate in &candidates {
        match inspect(token, candidate).await {
            Ok(()) => {
                tracing::info!(repository = %candidate.full_name, "admitted");
                admitted.push(format!("https://github.com/{}", candidate.full_name));
            }
            Err(InspectFailure::Rejected(reason)) => {
                tracing::info!(repository = %candidate.full_name, %reason, "rejected");
                rejected.push(Rejection {
                    repository: candidate.full_name.clone(),
                    reason,
                });
            }
            Err(InspectFailure::NotEvaluated(reason)) => {
                tracing::warn!(repository = %candidate.full_name, %reason, "not evaluated");
                not_evaluated.push(Rejection {
                    repository: candidate.full_name.clone(),
                    reason,
                });
            }
        }
    }
    if let Some(parent) = args.output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|error| stow_error!("create {}: {error}", parent.display()))?;
    }
    fs::write(&args.output, render_projects_file(&admitted))
        .map_err(|error| stow_error!("write {}: {error}", args.output.display()))?;
    let report = GenerateReport {
        file: args.output.display().to_string(),
        scanned: candidates.len(),
        admitted,
        rejected,
        not_evaluated,
    };
    render::emit(output, &report, |report| {
        let mut out = format!(
            "admitted {}/{} candidate repositories → {}\n",
            report.admitted.len(),
            report.scanned,
            report.file
        );
        if !report.rejected.is_empty() {
            let mut table = Table::new(&["repository", "reason"]);
            for rejection in &report.rejected {
                table.push([rejection.repository.clone(), rejection.reason.clone()]);
            }
            let _ = write!(out, "\nrejected\n{}", table.render());
        }
        if !report.not_evaluated.is_empty() {
            let mut table = Table::new(&["repository", "reason"]);
            for failure in &report.not_evaluated {
                table.push([failure.repository.clone(), failure.reason.clone()]);
            }
            let _ = write!(
                out,
                "\nnot evaluated (transport failures — the admission rule never ran)\n{}",
                table.render()
            );
        }
        out
    })
}

/// `preheat projects submit` — resolve the list, render the plan, apply
/// under `--yes`.
async fn submit(edge: &Edge, args: &SubmitArgs, output: Output) -> stow_types::error::Result<()> {
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_error!("preheat rustc_version: {error}"))?;
    let targets: Vec<TargetTriple> = crate::preheat::ci_targets(args.targets.clone())?
        .into_iter()
        .map(|raw| {
            TargetTriple::parse(raw.clone())
                .map_err(|error| stow_error!("--targets `{raw}`: {error}"))
        })
        .collect::<stow_types::error::Result<_>>()?;
    let repos = load_projects_file(&args.file)?;
    let scratch = std::env::temp_dir().join(format!("stow-admin-projects-{}", std::process::id()));
    let mut plan = ProjectsPlan {
        file: args.file.display().to_string(),
        tasks: Vec::new(),
        per_repo: Vec::with_capacity(repos.len()),
        skipped: Vec::new(),
    };
    for (index, repo) in repos.iter().enumerate() {
        let workdir = scratch.join(index.to_string());
        match resolve_repository(repo, &workdir, &targets, &rustc_version).await {
            Ok(tasks) => {
                tracing::info!(%repo, tasks = tasks.len(), "resolved");
                plan.per_repo.push(RepoContribution {
                    repo: repo.clone(),
                    tasks: tasks.len(),
                });
                plan.tasks.extend(tasks);
            }
            Err(error) => {
                tracing::warn!(%repo, reason = %error, "skipped");
                plan.skipped.push(SkippedRepo {
                    repo: repo.clone(),
                    reason: error.to_string(),
                });
            }
        }
        // The checkout is consumed into tasks already — drop the bytes
        // before the next repository lands.
        let _ = fs::remove_dir_all(&workdir);
    }
    let _ = fs::remove_dir_all(&scratch);
    render::mutation(
        output,
        args.yes,
        plan,
        |envelope: &render::Planned<ProjectsPlan, SubmitOutcome>| {
            let plan = &envelope.plan;
            let mut out = format!(
                "{} task(s) from {} repositories\n",
                plan.tasks.len(),
                plan.per_repo.len()
            );
            if !plan.per_repo.is_empty() {
                let mut table = Table::new(&["repository", "tasks"]);
                for contribution in &plan.per_repo {
                    table.push([contribution.repo.clone(), contribution.tasks.to_string()]);
                }
                let _ = write!(out, "{}", table.render());
            }
            if !plan.skipped.is_empty() {
                let mut table = Table::new(&["repository", "reason"]);
                for skipped in &plan.skipped {
                    table.push([skipped.repo.clone(), skipped.reason.clone()]);
                }
                let _ = write!(out, "\nskipped\n{}", table.render());
            }
            if let Some(result) = &envelope.result {
                let _ = write!(
                    out,
                    "\nsubmitted {}, inserted {}, dropped {} in {} batch(es)",
                    result.submitted, result.inserted, result.dropped, result.batches
                );
            }
            let _ = write!(out, "\n{}", render::plan_footer(envelope.dry_run));
            out
        },
        async move |plan: &ProjectsPlan| submit_chunked(edge, &plan.tasks).await,
    )
    .await
}

/// `GET /search/repositories?q=language:rust+stars:>N&sort=stars`, paged
/// up to `limit` candidates — the one query the generator ever runs.
async fn search(
    token: &str,
    min_stars: u64,
    limit: usize,
) -> stow_types::error::Result<Vec<SearchItem>> {
    let mut items = Vec::with_capacity(limit.min(SEARCH_HARD_LIMIT));
    for page in 1..=SEARCH_HARD_LIMIT.div_ceil(SEARCH_PER_PAGE) {
        let response: SearchPage = github::get_path(
            token,
            &format!(
                "/search/repositories?q=language:rust+stars%3A%3E{min_stars}&sort=stars&order=desc&per_page={SEARCH_PER_PAGE}&page={page}"
            ),
        )
        .await?;
        let exhausted = response.items.is_empty();
        items.extend(response.items);
        if exhausted || items.len() >= limit {
            break;
        }
    }
    items.truncate(limit);
    Ok(items)
}

/// Why one candidate did not land on the list.
enum InspectFailure {
    /// The tree answered and the admission rule spoke — this says
    /// something about the repository.
    Rejected(String),
    /// A transport failure — an IP-allowlist 403, an unreachable API —
    /// answered before the tree could be read. This says nothing about
    /// the repository, only about the network the run happened from.
    NotEvaluated(String),
}

/// Admission for one candidate: its default-branch git tree must carry a
/// `Cargo.lock` beside a `Cargo.toml`. The reason string is what the
/// reviewer sees on the rejection report.
async fn inspect(token: &str, candidate: &SearchItem) -> Result<(), InspectFailure> {
    let Some(branch) = candidate.default_branch.as_deref() else {
        return Err(InspectFailure::Rejected("no default branch".to_owned()));
    };
    let tree: TreeResponse = github::get_path(
        token,
        &format!(
            "/repos/{}/git/trees/{}?recursive=1",
            candidate.full_name,
            url_path_escape(branch)
        ),
    )
    .await
    .map_err(|error| InspectFailure::NotEvaluated(format!("git tree fetch failed: {error}")))?;
    let paths: Vec<String> = tree
        .tree
        .into_iter()
        .filter(|entry| entry.kind == "blob")
        .map(|entry| entry.path)
        .collect();
    if select_manifest(&paths).is_some() {
        return Ok(());
    }
    if tree.truncated {
        return Err(InspectFailure::Rejected(
            "git tree listing truncated before a Cargo.lock was found".to_owned(),
        ));
    }
    if paths.iter().any(|path| is_cargo_lock(path)) {
        return Err(InspectFailure::Rejected(
            "Cargo.lock present but not beside a Cargo.toml".to_owned(),
        ));
    }
    Err(InspectFailure::Rejected(
        "no Cargo.lock in the repository tree".to_owned(),
    ))
}

/// The manifest a lockfile roots: the shallowest `Cargo.lock` whose
/// directory also carries `Cargo.toml`. Nothing about subdirectories is
/// assumed — `src-tauri/`, `rust/`, `cli/`, `crates/` all admit the same
/// way. `paths` is every file path in the tree (or checkout).
fn select_manifest(paths: &[String]) -> Option<String> {
    let available: BTreeSet<&str> = paths.iter().map(String::as_str).collect();
    let mut lockfiles: Vec<&str> = paths
        .iter()
        .map(String::as_str)
        .filter(|path| is_cargo_lock(path))
        .collect();
    // Shallowest first, lexicographic within a depth — deterministic for
    // both the API listing and the filesystem walk that feeds it.
    lockfiles.sort_by(|a, b| path_depth(a).cmp(&path_depth(b)).then_with(|| a.cmp(b)));
    lockfiles.into_iter().find_map(|lockfile| {
        let manifest = match lockfile.rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/Cargo.toml"),
            None => "Cargo.toml".to_owned(),
        };
        available.contains(manifest.as_str()).then_some(manifest)
    })
}

/// True when `path` names a `Cargo.lock` file.
fn is_cargo_lock(path: &str) -> bool {
    path.rsplit('/').next() == Some("Cargo.lock")
}

/// Directory depth of a repository-relative path — the `/` count.
fn path_depth(path: &str) -> usize {
    path.bytes().filter(|byte| *byte == b'/').count()
}

/// Escape a git ref for use inside an API path — `/` is the one
/// separator that must not reach the route verbatim.
fn url_path_escape(segment: &str) -> String {
    segment.replace('%', "%25").replace('/', "%2F")
}

/// Render the committed list: the schema header plus one `[[project]]`
/// row per admitted repository, in list (stars-descending) order.
fn render_projects_file(repos: &[String]) -> String {
    let mut out = String::from(PROJECTS_HEADER);
    for repo in repos {
        let _ = writeln!(out, "[[project]]\nrepo = \"{repo}\"\n");
    }
    out
}

/// Read and validate `preheat/projects.toml` into its repository URLs.
fn load_projects_file(path: &Path) -> stow_types::error::Result<Vec<String>> {
    let raw = fs::read(path).map_err(|error| stow_error!("read {}: {error}", path.display()))?;
    let file: ProjectsFile =
        toml::from_slice(&raw).map_err(|error| stow_error!("parse {}: {error}", path.display()))?;
    if file.project.is_empty() {
        return Err(stow_error!("{} lists no repositories", path.display()));
    }
    file.project
        .iter()
        .map(|entry| normalize_repo_url(&entry.repo))
        .collect()
}

/// Normalize a listed repository to `https://github.com/<owner>/<name>`:
/// strip a trailing `.git` or `/`, then demand exactly the two path
/// segments GitHub carries.
fn normalize_repo_url(raw: &str) -> stow_types::error::Result<String> {
    let trimmed = raw.trim().trim_end_matches('/').trim_end_matches(".git");
    let Some(tail) = trimmed.strip_prefix("https://github.com/") else {
        return Err(stow_error!(
            "projects.toml repo `{raw}` must be https://github.com/<owner>/<name>"
        ));
    };
    let segments: Vec<&str> = tail.split('/').collect();
    if segments.len() != 2 || segments.iter().any(|segment| segment.is_empty()) {
        return Err(stow_error!(
            "projects.toml repo `{raw}` must be https://github.com/<owner>/<name>"
        ));
    }
    Ok(format!("https://github.com/{tail}"))
}

/// Resolve one listed repository into its enqueue batch: shallow-clone,
/// drop the committed lockfile so cargo re-resolves to the latest
/// semver-compatible versions, then `cargo metadata --filter-platform`
/// once per target.
async fn resolve_repository(
    repo: &str,
    workdir: &Path,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<Vec<EnqueueRequest>> {
    clone(repo, workdir).await?;
    let paths = collect_manifest_paths(workdir)?;
    let manifest = select_manifest(&paths)
        .ok_or_else(|| stow_error!("{repo}: no Cargo.lock beside a Cargo.toml in the checkout"))?;
    // Versions converge: the committed lockfile's pins are dropped so the
    // resolve lands on the latest semver-compatible version — a project
    // contributes crate names and feature sets, never version pins.
    fs::remove_file(workdir.join(manifest_dir(&manifest)).join("Cargo.lock"))
        .map_err(|error| stow_error!("{repo}: delete Cargo.lock: {error}"))?;
    let manifest_path = workdir.join(&manifest);
    tasks_for_manifest(&manifest_path, targets, rustc_version, 0).await
}

/// `cargo metadata --filter-platform` over one manifest, once per
/// target, into the whole task batch — the pass every name-source lane
/// (projects, binaries) shares. `downloads` is the source's own
/// property: the binaries lane passes the binary's crates.io download
/// count, the projects lane passes `0` (stars are not a download
/// signal).
pub async fn tasks_for_manifest(
    manifest_path: &Path,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    downloads: u64,
) -> stow_types::error::Result<Vec<EnqueueRequest>> {
    let mut tasks = Vec::new();
    for target in targets {
        let metadata = metadata(manifest_path, target).await?;
        tasks.extend(tasks_from_metadata(
            &metadata,
            target,
            rustc_version,
            downloads,
        )?);
    }
    Ok(tasks)
}

/// The directory half of a manifest path (`""` at the root).
fn manifest_dir(manifest: &str) -> &str {
    manifest.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// `git clone --depth 1` into `workdir`.
async fn clone(repo: &str, workdir: &Path) -> stow_types::error::Result<()> {
    let output = smol::process::Command::new("git")
        .args(["clone", "--quiet", "--depth", "1", repo])
        .arg(workdir)
        .output()
        .await
        .map_err(|error| stow_error!("{repo}: run `git clone`: {error}"))?;
    if !output.status.success() {
        return Err(stow_error!(
            "{repo}: git clone failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// `cargo metadata --format-version 1 --filter-platform <triple>` on the
/// selected manifest, resolved under the stable toolchain so a
/// repository's `rust-toolchain.toml` cannot redirect resolution.
pub async fn metadata(
    manifest_path: &Path,
    target: &TargetTriple,
) -> stow_types::error::Result<Metadata> {
    let output = smol::process::Command::new("cargo")
        .env("RUSTUP_TOOLCHAIN", RESOLVE_TOOLCHAIN)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--filter-platform",
            target.as_str(),
            "--manifest-path",
        ])
        .arg(manifest_path)
        .output()
        .await
        .map_err(|error| stow_error!("run `cargo metadata`: {error}"))?;
    if !output.status.success() {
        return Err(stow_error!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| stow_error!("parse `cargo metadata` output: {error}"))
}

/// The lockfile and manifest paths in one checkout — `collect_manifest_paths`
/// walks the tree so `select_manifest` can apply its admission rule the
/// same way it does to the git-trees listing.
fn collect_manifest_paths(root: &Path) -> stow_types::error::Result<Vec<String>> {
    let mut paths = Vec::new();
    collect_paths(root, Path::new(""), &mut paths)
        .map_err(|error| stow_error!("walk {}: {error}", root.display()))?;
    Ok(paths)
}

/// Recursively collect repository-relative paths of `Cargo.lock` and
/// `Cargo.toml` files — the only two names `select_manifest` reads.
fn collect_paths(dir: &Path, prefix: &Path, out: &mut Vec<String>) -> std::io::Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        if entry.file_name() == ".git" {
            continue;
        }
        let relative = prefix.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            collect_paths(&entry.path(), &relative, out)?;
        } else if matches!(
            entry.file_name().to_str(),
            Some("Cargo.lock" | "Cargo.toml")
        ) {
            out.push(relative.to_string_lossy().into_owned());
        }
    }
    Ok(())
}

/// Every crates.io node in `resolve`, as one task per node at the
/// resolved feature set, each carrying its crates.io dependencies as
/// `depends_on` edges at the same `(target, rustc_version)`.
///
/// Packages from anywhere else — git deps, path members, alternative
/// registries — are skipped: the cache has no identity to publish them
/// under. So is a package with nothing `ArtifactKind` covers — a
/// bin-only crate can legally sit in `resolve` as a dependency, but it
/// compiles to nothing the pipeline publishes. Edges pointing at either
/// kind are dropped the same way, and edges to packages the platform
/// filter removed simply cannot resolve.
pub fn tasks_from_metadata(
    metadata: &Metadata,
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
    downloads: u64,
) -> stow_types::error::Result<Vec<EnqueueRequest>> {
    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or_else(|| stow_error!("cargo metadata reported no resolve graph"))?;
    let packages: HashMap<&PackageId, &cargo_metadata::Package> = metadata
        .packages
        .iter()
        .map(|package| (&package.id, package))
        .collect();
    let nodes: HashMap<&PackageId, &cargo_metadata::Node> =
        resolve.nodes.iter().map(|node| (&node.id, node)).collect();
    let mut tasks = Vec::new();
    for node in &resolve.nodes {
        let Some(package) = packages.get(&node.id) else {
            continue;
        };
        if !package
            .source
            .as_ref()
            .is_some_and(cargo_metadata::Source::is_crates_io)
            || !publishes_artifact(package)
        {
            continue;
        }
        let mut depends_on = Vec::new();
        let mut seen = BTreeSet::new();
        for dep in &node.deps {
            if !edge_needed(dep) || !seen.insert(dep.pkg.repr.clone()) {
                continue;
            }
            let (Some(dep_node), Some(dep_package)) = (nodes.get(&dep.pkg), packages.get(&dep.pkg))
            else {
                continue;
            };
            if !dep_package
                .source
                .as_ref()
                .is_some_and(cargo_metadata::Source::is_crates_io)
                || !publishes_artifact(dep_package)
            {
                continue;
            }
            depends_on.push(EnqueueDependency {
                crate_name: CrateName::parse(dep_package.name.as_str())
                    .map_err(|error| stow_error!("dependency crate_name: {error}"))?,
                version: TypedCrateVersion::new(dep_package.version.clone()),
                features_json: features_json(&dep_node.features)?,
                target: target.clone(),
                rustc_version: rustc_version.clone(),
            });
        }
        tasks.push(EnqueueRequest {
            crate_name: CrateName::parse(package.name.as_str())
                .map_err(|error| stow_error!("crate_name: {error}"))?,
            version: TypedCrateVersion::new(package.version.clone()),
            features_json: features_json(&node.features)?,
            target: target.clone(),
            rustc_version: rustc_version.clone(),
            downloads,
            source: EnqueueSource::CrateUpdate,
            depends_on,
            // A derived task carries no lockfile of its own to preserve:
            // the source's pins are already baked into `version` and
            // `features_json` by the resolve above, and on the runner the
            // flag would name the task crate's own published lockfile
            // instead of the source's.
            preserve_lockfile: false,
        });
    }
    Ok(tasks)
}

/// Does this package compile to something the pipeline publishes?
/// `ArtifactKind` covers rlib, dylib and proc-macro — a package whose
/// manifest declares none of those (a bin-only crate, legal as a
/// dependency) is a name source like the root package, never a task.
fn publishes_artifact(package: &cargo_metadata::Package) -> bool {
    package.targets.iter().any(|target| {
        target.kind.iter().any(|kind| {
            matches!(
                kind,
                TargetKind::Lib | TargetKind::DyLib | TargetKind::ProcMacro
            )
        })
    })
}

/// Does a `resolve` edge reach code this build compiles? Cargo lists
/// build- and normal-kind dependencies; a development-only edge produces
/// nothing the target build consumes, and an empty `dep_kinds` is how
/// the API spells a plain dependency.
fn edge_needed(dep: &cargo_metadata::NodeDep) -> bool {
    dep.dep_kinds.is_empty()
        || dep
            .dep_kinds
            .iter()
            .any(|kind| matches!(kind.kind, DependencyKind::Normal | DependencyKind::Build))
}

/// The resolved feature set as the wire type — sorted, deduplicated,
/// validated.
fn features_json(
    features: &[cargo_metadata::FeatureName],
) -> stow_types::error::Result<FeaturesJson> {
    FeaturesJson::canonicalize(features.iter().map(|f| f.as_str().to_owned()).collect())
        .map_err(|error| stow_error!("features_json: {error}"))
}

/// POST the batch in [`SUBMIT_CHUNK`]-sized pieces and sum the responses
/// — a full wave is far over the edge's single-request bound.
pub async fn submit_chunked(
    edge: &Edge,
    tasks: &[EnqueueRequest],
) -> stow_types::error::Result<SubmitOutcome> {
    let mut outcome = SubmitOutcome {
        batches: 0,
        submitted: 0,
        inserted: 0,
        dropped: 0,
    };
    for chunk in tasks.chunks(SUBMIT_CHUNK) {
        let response: SchedulerSubmitResponse = crate::submit(edge, chunk).await?;
        outcome.batches += 1;
        outcome.submitted += response.submitted;
        outcome.inserted += response.inserted;
        outcome.dropped += response.dropped;
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `cargo metadata` package description in the shape the crate
    /// returns: `source` decides admission, `id` keys the resolve maps.
    fn package(name: &str, version: &str, source: Option<&str>) -> cargo_metadata::Package {
        serde_json::from_value(serde_json::json!({
            "name": name,
            "version": version,
            "id": format!("pkg#{name}@{version}"),
            "source": source,
            "edition": "2021",
            "authors": [],
            "dependencies": [],
            "features": {},
            "manifest_path": format!("/registry/{name}-{version}/Cargo.toml"),
            "targets": [{
                "kind": ["lib"],
                "crate_types": ["lib"],
                "name": name,
                "src_path": format!("/registry/{name}-{version}/src/lib.rs"),
                "edition": "2021",
            }],
        }))
        .expect("deserialize test package")
    }

    /// A crates.io package that ships only a binary — legal as a
    /// resolved dependency, useless as a task.
    fn bin_package(name: &str, version: &str, source: Option<&str>) -> cargo_metadata::Package {
        serde_json::from_value(serde_json::json!({
            "name": name,
            "version": version,
            "id": format!("pkg#{name}@{version}"),
            "source": source,
            "edition": "2021",
            "authors": [],
            "dependencies": [],
            "features": {},
            "manifest_path": format!("/registry/{name}-{version}/Cargo.toml"),
            "targets": [{
                "kind": ["bin"],
                "crate_types": ["bin"],
                "name": name,
                "src_path": format!("/registry/{name}-{version}/src/main.rs"),
                "edition": "2021",
            }],
        }))
        .expect("deserialize test package")
    }

    /// `cargo metadata` output for `packages`, with a resolve carrying
    /// `edges` — `(from, to, kind)` with `kind` in `{"normal", "build",
    /// "dev", null}` — and per-node `features`.
    fn metadata_with(
        packages: &[cargo_metadata::Package],
        edges: &[(&str, &str, Option<&str>)],
        features: &[(&str, &[&str])],
    ) -> Metadata {
        let nodes: Vec<serde_json::Value> = packages
            .iter()
            .map(|package| {
                let id = package.id.repr.clone();
                let deps: Vec<serde_json::Value> = edges
                    .iter()
                    .filter(|(from, _, _)| id == *from)
                    .map(|(_, to, kind)| {
                        let dep_kinds = kind.as_ref().map_or_else(
                            || serde_json::json!([]),
                            |kind| serde_json::json!([{ "kind": kind }]),
                        );
                        serde_json::json!({
                            "name": to.split('#').nth(1).and_then(|rest| rest.split('@').next()).unwrap_or(to),
                            "pkg": to,
                            "dep_kinds": dep_kinds,
                        })
                    })
                    .collect();
                let features: Vec<&str> = features
                    .iter()
                    .find(|(node, _)| *node == id)
                    .map_or_else(Vec::new, |(_, list)| list.to_vec());
                serde_json::json!({
                    "id": id,
                    "deps": deps,
                    "dependencies": [],
                    "features": features,
                })
            })
            .collect();
        serde_json::from_value(serde_json::json!({
            "packages": packages,
            "workspace_members": [packages[0].id.repr.clone()],
            "workspace_root": "/workspace",
            "target_directory": "/workspace/target",
            "version": 1,
            "resolve": {
                "nodes": nodes,
                "root": packages[0].id.repr.clone(),
            },
        }))
        .expect("deserialize test metadata")
    }

    fn target() -> TargetTriple {
        TargetTriple::parse("x86_64-unknown-linux-gnu").unwrap()
    }

    fn rustc() -> WireRustcVersion {
        WireRustcVersion::parse("1.89.0").unwrap()
    }

    fn task_ids(tasks: &[EnqueueRequest]) -> BTreeSet<String> {
        tasks
            .iter()
            .map(|task| {
                format!(
                    "{} {} {} {}",
                    task.crate_name.as_str(),
                    task.version,
                    task.features_json.raw(),
                    task.target.as_str()
                )
            })
            .collect()
    }

    #[test]
    fn manifest_at_root_wins_over_nested_ones() {
        let paths = vec![
            "Cargo.toml".to_owned(),
            "Cargo.lock".to_owned(),
            "src-tauri/Cargo.toml".to_owned(),
            "src-tauri/Cargo.lock".to_owned(),
        ];
        assert_eq!(select_manifest(&paths).as_deref(), Some("Cargo.toml"));
    }

    #[test]
    fn nested_lockfile_is_picked_when_root_has_none() {
        let paths = vec![
            "README.md".to_owned(),
            "src-tauri/Cargo.toml".to_owned(),
            "src-tauri/Cargo.lock".to_owned(),
        ];
        assert_eq!(
            select_manifest(&paths).as_deref(),
            Some("src-tauri/Cargo.toml")
        );
    }

    #[test]
    fn lockfile_without_sibling_manifest_is_not_admitted() {
        let paths = vec![
            "vendor/dep/Cargo.lock".to_owned(),
            "vendor/dep/src/lib.rs".to_owned(),
            "Cargo.toml".to_owned(),
        ];
        assert_eq!(select_manifest(&paths), None);
    }

    #[test]
    fn no_lockfile_is_rejected() {
        let paths = vec!["Cargo.toml".to_owned(), "src/lib.rs".to_owned()];
        assert_eq!(select_manifest(&paths), None);
    }

    #[test]
    fn shallowest_lockfile_wins_across_directories() {
        let paths = vec![
            "a/b/Cargo.toml".to_owned(),
            "a/b/Cargo.lock".to_owned(),
            "cli/Cargo.toml".to_owned(),
            "cli/Cargo.lock".to_owned(),
        ];
        assert_eq!(select_manifest(&paths).as_deref(), Some("cli/Cargo.toml"));
    }

    #[test]
    fn generated_file_round_trips_the_parser() {
        let repos = vec![
            "https://github.com/a/one".to_owned(),
            "https://github.com/b/two".to_owned(),
        ];
        let written = render_projects_file(&repos);
        let parsed: ProjectsFile = toml::from_str(&written).expect("generated file parses");
        assert_eq!(parsed.project.len(), 2);
        assert_eq!(parsed.project[0].repo, repos[0]);
    }

    #[test]
    fn projects_file_rejects_unknown_fields() {
        assert!(
            toml::from_str::<ProjectsFile>(
                "[[project]]\nrepo = \"https://github.com/a/b\"\ncommit = \"abc\"\n"
            )
            .is_err()
        );
        assert!(
            toml::from_str::<ProjectsFile>(
                "[[project]]\nrepo = \"https://github.com/a/b\"\n\nother = 1\n"
            )
            .is_err()
        );
    }

    #[test]
    fn repo_urls_normalize_and_reject() {
        assert_eq!(
            normalize_repo_url("https://github.com/a/b.git").unwrap(),
            "https://github.com/a/b"
        );
        assert_eq!(
            normalize_repo_url("https://github.com/a/b/").unwrap(),
            "https://github.com/a/b"
        );
        assert!(normalize_repo_url("git@github.com:a/b").is_err());
        assert!(normalize_repo_url("https://github.com/a").is_err());
        assert!(normalize_repo_url("https://github.com/a/b/c").is_err());
        assert!(normalize_repo_url("https://gitlab.com/a/b").is_err());
    }

    #[test]
    fn only_crates_io_nodes_become_tasks() {
        let registry = Some("registry+https://github.com/rust-lang/crates.io-index");
        let git = Some("git+https://github.com/example/dep#abc");
        let packages = vec![
            package("app", "1.0.0", None),
            package("mid", "2.0.0", registry),
            package("leaf", "3.0.0", registry),
            package("vend", "1.0.0", git),
        ];
        let root = packages[0].id.repr.clone();
        let mid = packages[1].id.repr.clone();
        let leaf = packages[2].id.repr.clone();
        let vend = packages[3].id.repr.clone();
        let metadata = metadata_with(
            &packages,
            &[
                (&root, &mid, Some("normal")),
                (&mid, &leaf, Some("normal")),
                (&mid, &vend, Some("normal")),
            ],
            &[(&mid, &["serde", "full"]), (&leaf, &[])],
        );
        let tasks = tasks_from_metadata(&metadata, &target(), &rustc(), 0).unwrap();
        let ids = task_ids(&tasks);
        assert_eq!(
            ids,
            BTreeSet::from([
                "mid 2.0.0 [\"full\",\"serde\"] x86_64-unknown-linux-gnu".to_owned(),
                "leaf 3.0.0 [] x86_64-unknown-linux-gnu".to_owned(),
            ])
        );
        let mid_task = tasks
            .iter()
            .find(|task| task.crate_name.as_str() == "mid")
            .unwrap();
        assert_eq!(mid_task.depends_on.len(), 1);
        let edge = &mid_task.depends_on[0];
        assert_eq!(edge.crate_name.as_str(), "leaf");
        assert_eq!(edge.version.as_semver().to_string(), "3.0.0");
        assert_eq!(edge.features_json.raw(), "[]");
        assert_eq!(edge.target.as_str(), "x86_64-unknown-linux-gnu");
        assert_eq!(edge.rustc_version.as_str(), "1.89.0");
    }

    #[test]
    fn dev_only_edges_are_not_emitted() {
        let registry = Some("registry+https://github.com/rust-lang/crates.io-index");
        let packages = vec![
            package("mid", "2.0.0", registry),
            package("devdep", "1.0.0", registry),
            package("normaldep", "1.0.0", registry),
            package("builddep", "1.0.0", registry),
            package("plaindep", "1.0.0", registry),
        ];
        let mid = packages[0].id.repr.clone();
        let devdep = packages[1].id.repr.clone();
        let normaldep = packages[2].id.repr.clone();
        let builddep = packages[3].id.repr.clone();
        let plaindep = packages[4].id.repr.clone();
        let metadata = metadata_with(
            &packages,
            &[
                (&mid, &devdep, Some("dev")),
                (&mid, &normaldep, Some("normal")),
                (&mid, &builddep, Some("build")),
                (&mid, &plaindep, None),
            ],
            &[(&mid, &[])],
        );
        let tasks = tasks_from_metadata(&metadata, &target(), &rustc(), 0).unwrap();
        let mid_task = tasks
            .iter()
            .find(|task| task.crate_name.as_str() == "mid")
            .unwrap();
        let dep_names: BTreeSet<&str> = mid_task
            .depends_on
            .iter()
            .map(|dep| dep.crate_name.as_str())
            .collect();
        assert_eq!(
            dep_names,
            BTreeSet::from(["normaldep", "builddep", "plaindep"])
        );
    }

    #[test]
    fn edge_features_come_from_the_resolved_node() {
        let registry = Some("registry+https://github.com/rust-lang/crates.io-index");
        let packages = vec![
            package("mid", "2.0.0", registry),
            package("dep", "1.0.0", registry),
        ];
        let mid = packages[0].id.repr.clone();
        let dep = packages[1].id.repr.clone();
        let metadata = metadata_with(
            &packages,
            &[(&mid, &dep, Some("normal"))],
            &[(&mid, &["x"]), (&dep, &["y", "z"])],
        );
        let tasks = tasks_from_metadata(&metadata, &target(), &rustc(), 0).unwrap();
        let mid_task = tasks
            .iter()
            .find(|task| task.crate_name.as_str() == "mid")
            .unwrap();
        assert_eq!(mid_task.depends_on[0].features_json.raw(), "[\"y\",\"z\"]");
    }

    /// A crates.io package that declares no publishable target — a
    /// bin-only crate, legal in a resolve — is a name source like the
    /// root package: no task, and no `depends_on` edge can dangle at it.
    #[test]
    fn bin_only_packages_never_become_tasks_or_edges() {
        let registry = Some("registry+https://github.com/rust-lang/crates.io-index");
        let packages = vec![
            package("mid", "2.0.0", registry),
            package("leaf", "3.0.0", registry),
            bin_package("tool", "9.9.9", registry),
        ];
        let mid = packages[0].id.repr.clone();
        let leaf = packages[1].id.repr.clone();
        let tool = packages[2].id.repr.clone();
        let metadata = metadata_with(
            &packages,
            &[(&mid, &leaf, Some("normal")), (&mid, &tool, Some("normal"))],
            &[(&mid, &[])],
        );
        let tasks = tasks_from_metadata(&metadata, &target(), &rustc(), 0).unwrap();
        let ids = task_ids(&tasks);
        assert_eq!(
            ids,
            BTreeSet::from([
                "mid 2.0.0 [] x86_64-unknown-linux-gnu".to_owned(),
                "leaf 3.0.0 [] x86_64-unknown-linux-gnu".to_owned(),
            ])
        );
        let mid_task = tasks
            .iter()
            .find(|task| task.crate_name.as_str() == "mid")
            .unwrap();
        assert_eq!(
            mid_task
                .depends_on
                .iter()
                .map(|dep| dep.crate_name.as_str())
                .collect::<Vec<_>>(),
            ["leaf"]
        );
    }
}
