//! `stow-admin preheat projects …` — the stars-ranked preheat lane.
//!
//! `generate` refreshes `preheat/projects.toml`: every entry already in
//! the file is re-evaluated under the admission rule — its git tree
//! carrying a `Cargo.lock` beside a `Cargo.toml`, shallowest first — and
//! stays while it passes, whether the star sweep named it or a human
//! merged it; the sweep only discovers new candidates. A listed entry
//! whose evaluation never ran — a transport failure says nothing about
//! the repository — stays in the file. Every rejection is reported with
//! its reason. The list is generated and merged by a human — nothing
//! here is ever queried live during a wave.
//!
//! `submit` turns each listed repository into ordinary crate tasks: the
//! checkout's committed lockfile is deleted so cargo re-resolves to the
//! latest semver-compatible versions, one unfiltered `cargo metadata`
//! resolve is walked per CI target, and every reachable crates.io
//! `(package, compile side)` node is enqueued at its side's feature set
//! with its crates.io dependencies as `depends_on` edges. A repository
//! that fails to resolve is reported and skipped — one bad manifest
//! must not sink the wave.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use cargo_metadata::{DependencyKind, Metadata, PackageId, TargetKind};
use clap::{Args, Subcommand};
use futures_util::{StreamExt, stream};
use stow_types::api::{
    EnqueueDependency, EnqueueRequest, EnqueueSource, RunnerFamily, SchedulerSubmitResponse,
    runner_family,
};
use stow_types::dep_graph::{self, CompileSide};
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
    /// Refresh `preheat/projects.toml`: re-evaluate every listed entry
    /// under the admission rule, then append newly admitted candidates
    /// from GitHub's most-starred Rust repositories. Writes the merged
    /// list and prints a rejection report; the weekly job that runs
    /// this opens the pull request.
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

/// The `GET /repos/{owner}/{name}` record — the field re-evaluating a
/// listed entry needs.
#[derive(Debug, serde::Deserialize)]
struct RepoRecord {
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

/// What `generate` reports: the file it wrote, the listed entries that
/// stayed, every new admission, and every rejection with its reason.
#[derive(Debug, serde::Serialize)]
struct GenerateReport {
    /// The file the list was written to.
    file: String,
    /// How many candidates the sweep inspected.
    scanned: usize,
    /// Already-listed entries that stay — either still admitted or never
    /// evaluated — in their existing order.
    kept: Vec<String>,
    /// Newly admitted sweep candidates, in sweep order.
    admitted: Vec<String>,
    /// Rejected repositories with their reasons — listed entries that
    /// failed re-evaluation and swept candidates alike.
    rejected: Vec<Rejection>,
    /// Candidates the admission rule never evaluated — a transport
    /// failure (an IP-allowlist 403, an unreachable API) answered before
    /// the tree could be read. A listed entry stays in the file; a swept
    /// candidate is simply not added. Distinct from `rejected` so a
    /// reader does not conclude these repositories failed the filter.
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
# The list is generated and reviewed: `stow-admin preheat projects
# generate` re-evaluates every entry under the same admission rule — a
# git tree holding a Cargo.lock next to the workspace manifest — and
# `preheat-projects.yml` opens the diff as a pull request. An entry
# stays while it passes, whether the star sweep named it or a human
# merged it; the sweep only discovers new candidates. A library commits
# no lockfile by convention and drops out — the download-ranked lane
# covers those. Review the diff before merging: an entry spends runner
# minutes on every wave.
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

/// `preheat projects generate` — merge the reviewed list with the
/// sweep: re-evaluate every listed entry, admit new candidates, write
/// the file, report.
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
    // The merge starts from the file itself: a missing file is a first
    // run and starts empty, while one that fails to parse is an error,
    // not an empty list. `submit` reads it through the same loader, so
    // the two agree on what a repository URL is.
    let existing = if args.output.exists() {
        load_projects_file(&args.output)?
    } else {
        Vec::new()
    };
    let (verdicts, mut rejected, mut not_evaluated) = reevaluate_listed(token, &existing).await;
    let candidates = search(token, args.min_stars, args.limit).await?;
    let (admitted, sweep_rejected, sweep_unevaluated) =
        evaluate_sweep(token, &candidates, &existing).await?;
    rejected.extend(sweep_rejected);
    not_evaluated.extend(sweep_unevaluated);
    let merged = merge_listed(&verdicts, &admitted);
    if let Some(parent) = args.output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|error| stow_error!("create {}: {error}", parent.display()))?;
    }
    fs::write(&args.output, render_projects_file(&merged))
        .map_err(|error| stow_error!("write {}: {error}", args.output.display()))?;
    let report = GenerateReport {
        file: args.output.display().to_string(),
        scanned: candidates.len(),
        kept: verdicts
            .iter()
            .filter(|(_, verdict)| !matches!(verdict, ListedVerdict::Rejected))
            .map(|(url, _)| url.clone())
            .collect(),
        admitted,
        rejected,
        not_evaluated,
    };
    render::emit(output, &report, |report| {
        let mut out = format!(
            "kept {} listed, admitted {}/{} swept candidates → {}\n",
            report.kept.len(),
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

/// Concurrent GitHub API fetches while a generate run walks the list.
/// Each repository costs two requests — its record, then its git tree —
/// and GitHub's secondary rate limits penalise bursts of concurrent
/// requests, so the fan-out stays modest.
const GITHUB_FETCH_CONCURRENCY: usize = 8;

/// File one repository's admission outcome into the report: logs the
/// verdict, records the reason on the rejection or not-evaluated table,
/// and returns the verdict so the caller can route the entry.
fn record_verdict(
    repository: &str,
    outcome: Result<(), InspectFailure>,
    rejected: &mut Vec<Rejection>,
    not_evaluated: &mut Vec<Rejection>,
) -> ListedVerdict {
    match outcome {
        Ok(()) => {
            tracing::info!(repository = %repository, "admitted");
            ListedVerdict::Admitted
        }
        Err(InspectFailure::Rejected(reason)) => {
            tracing::info!(repository = %repository, %reason, "rejected");
            rejected.push(Rejection {
                repository: repository.to_owned(),
                reason,
            });
            ListedVerdict::Rejected
        }
        Err(InspectFailure::NotEvaluated(reason)) => {
            tracing::warn!(repository = %repository, %reason, "not evaluated");
            not_evaluated.push(Rejection {
                repository: repository.to_owned(),
                reason,
            });
            ListedVerdict::NotEvaluated
        }
    }
}

/// Re-evaluate every entry the file already lists under the same
/// admission rule the sweep uses — the file is the merge's input, not
/// its cache. A listed entry that now fails drops out with its reason;
/// one the rule never evaluated stays (a transport failure says nothing
/// about the repository). An entry listed twice evaluates once.
async fn reevaluate_listed(
    token: &str,
    existing: &[String],
) -> (Vec<(String, ListedVerdict)>, Vec<Rejection>, Vec<Rejection>) {
    // An entry listed twice evaluates once — the first slot's verdict
    // stands for the repository.
    let mut listed: BTreeSet<&String> = BTreeSet::new();
    let unique: Vec<&String> = existing.iter().filter(|url| listed.insert(*url)).collect();
    // `buffered` keeps the answers in the file's order, which is the
    // order the merge preserves.
    let inspected = stream::iter(unique)
        .map(|url| async move {
            let full_name = url.trim_start_matches("https://github.com/");
            (url, inspect_listed(token, full_name).await)
        })
        .buffered(GITHUB_FETCH_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut verdicts = Vec::with_capacity(inspected.len());
    let mut rejected = Vec::new();
    let mut not_evaluated = Vec::new();
    for (url, outcome) in inspected {
        let full_name = url.trim_start_matches("https://github.com/");
        let verdict = record_verdict(full_name, outcome, &mut rejected, &mut not_evaluated);
        verdicts.push((url.clone(), verdict));
    }
    (verdicts, rejected, not_evaluated)
}

/// Sweep the star search for new candidates: an entry the file already
/// lists was re-evaluated and the sweep does not get a second say on
/// it, so only unlisted candidates run the admission rule.
async fn evaluate_sweep(
    token: &str,
    candidates: &[SearchItem],
    existing: &[String],
) -> stow_types::error::Result<(Vec<String>, Vec<Rejection>, Vec<Rejection>)> {
    let listed: BTreeSet<&String> = existing.iter().collect();
    // Listed repositories are skipped before the network ever runs —
    // the sweep has nothing to say about them and the fetches would be
    // wasted calls.
    let mut unlisted = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let url = normalize_repo_url(&format!("https://github.com/{}", candidate.full_name))?;
        if !listed.contains(&url) {
            unlisted.push((candidate, url));
        }
    }
    // `buffered` keeps the answers in sweep (stars-descending) order,
    // which is the order the merge appends them in.
    let inspected = stream::iter(unlisted)
        .map(|(candidate, url)| async move { (candidate, url, inspect(token, candidate).await) })
        .buffered(GITHUB_FETCH_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut admitted = Vec::new();
    let mut rejected = Vec::new();
    let mut not_evaluated = Vec::new();
    for (candidate, url, outcome) in inspected {
        if matches!(
            record_verdict(
                &candidate.full_name,
                outcome,
                &mut rejected,
                &mut not_evaluated
            ),
            ListedVerdict::Admitted
        ) {
            admitted.push(url);
        }
    }
    Ok((admitted, rejected, not_evaluated))
}

/// What the admission rule said about one already-listed repository.
enum ListedVerdict {
    /// Still passes — stays.
    Admitted,
    /// Fails now — drops out and reports its reason.
    Rejected,
    /// Never ran — a transport failure says nothing about the
    /// repository, so the entry stays.
    NotEvaluated,
}

/// The merged list `generate` writes: listed entries in their existing
/// order minus the ones the rule now rejects, then newly admitted sweep
/// candidates not already listed.
fn merge_listed(verdicts: &[(String, ListedVerdict)], admitted: &[String]) -> Vec<String> {
    let mut merged = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (url, verdict) in verdicts {
        if !seen.insert(url.as_str()) {
            continue;
        }
        if !matches!(verdict, ListedVerdict::Rejected) {
            merged.push(url.clone());
        }
    }
    for url in admitted {
        if seen.insert(url.as_str()) {
            merged.push(url.clone());
        }
    }
    merged
}

/// Re-evaluate one listed repository under the admission rule the sweep
/// uses: its `GET /repos/{owner}/{name}` record supplies the default
/// branch a search item would have carried, and the same git-trees
/// check decides. A 404 is the repository being gone — a fact about the
/// repository, so it rejects — while any other failure to read the
/// record says nothing about it.
async fn inspect_listed(token: &str, full_name: &str) -> Result<(), InspectFailure> {
    let record: RepoRecord = match github::get_path_result(token, &format!("/repos/{full_name}"))
        .await
    {
        Ok(record) => record,
        Err(zenwave::Error::Http { status, .. }) if status == zenwave::StatusCode::NOT_FOUND => {
            return Err(InspectFailure::Rejected("repository not found".to_owned()));
        }
        Err(error) => {
            return Err(InspectFailure::NotEvaluated(format!(
                "repository fetch failed: {error}"
            )));
        }
    };
    inspect(
        token,
        &SearchItem {
            full_name: full_name.to_owned(),
            default_branch: record.default_branch,
        },
    )
    .await
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

/// One unfiltered `cargo metadata` over the manifest, walked once per
/// CI target, into the whole task batch — the pass every name-source
/// lane (projects, binaries) shares. `downloads` is the source's own
/// property: the binaries lane passes the binary's crates.io download
/// count, the projects lane passes `0` (stars are not a download
/// signal).
pub async fn tasks_for_manifest(
    manifest_path: &Path,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    downloads: u64,
) -> stow_types::error::Result<Vec<EnqueueRequest>> {
    let metadata = metadata(manifest_path).await?;
    let mut tasks = Vec::new();
    for target in targets {
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

/// `cargo metadata --format-version 1` on the selected manifest,
/// resolved under the stable toolchain so a repository's
/// `rust-toolchain.toml` cannot redirect resolution.
///
/// Deliberately unfiltered: `--filter-platform` prunes dep edges
/// evaluated against the consumer's target for *every* dep kind, so a
/// build dependency gated on a host-only cfg — `cfg(unix)` under a
/// `wasm32` consumer — would be dropped before the host-side walk could
/// see it. The resolve reports every platform's edges; each carries its
/// dep kind and platform spec, and `tasks_from_metadata` evaluates the
/// spec against the triple of the side the dep compiles for.
pub async fn metadata(manifest_path: &Path) -> stow_types::error::Result<Metadata> {
    let output = smol::process::Command::new("cargo")
        .env("RUSTUP_TOOLCHAIN", RESOLVE_TOOLCHAIN)
        .args(["metadata", "--format-version", "1", "--manifest-path"])
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

/// Every `(package, compile side)` node reachable in `resolve`, as one
/// task per publishable node at the side's feature set and triple, each
/// carrying its publishable dependencies as `depends_on` edges pointing
/// at the dep's own side.
///
/// Cargo compiles proc-macro crates, and every package reached only
/// through build-dependency or proc-macro edges, for the host — on a
/// `wasm32` consumer build the whole proc-macro/build-script subgraph
/// runs at `x86_64-unknown-linux-gnu`, and its feature activation is the
/// one cargo computes for `CompileKind::Host`, not the union the
/// resolve's per-node `features` report. The walk therefore splits the
/// graph itself: a node is `(package, side)`, an edge lands on
/// [`CompileSide::Host`] when the dep is a build dependency or a
/// proc-macro lib or its parent is already host-side, and each node's
/// feature set is re-expanded per side from the declared `[features]`
/// table and the seeds arriving on that side's edges — the same
/// expansion the edge's crates.io closure runs over index data. A
/// package compiled on both sides becomes two tasks whose different
/// `features_json`/`target` keep their identities distinct; when they
/// coincide, the one build produces both cargo units.
///
/// A dep's `target` spec is evaluated against the triple of the side it
/// compiles for, not the consumer's: a `cfg(unix)` build dependency
/// holds on a `wasm32` build because the build script runs on the Linux
/// host.
///
/// Packages from anywhere else — git deps, path members, alternative
/// registries — are skipped at emission: the cache has no identity to
/// publish them under. So is a package with nothing `ArtifactKind`
/// covers — a bin-only crate can legally sit in `resolve` as a
/// dependency, but it compiles to nothing the pipeline publishes. Both
/// still propagate side and feature seeds to their own dependencies,
/// the same way cargo still compiles them.
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
    let host_triple = runner_family(target.as_str())
        .map(RunnerFamily::host_triple)
        .ok_or_else(|| stow_error!("no runner family for target {}", target.as_str()))?;
    let host_target = TargetTriple::parse(host_triple)
        .map_err(|error| stow_error!("host triple {host_triple}: {error}"))?;
    let packages: HashMap<&PackageId, &cargo_metadata::Package> = metadata
        .packages
        .iter()
        .map(|package| (&package.id, package))
        .collect();
    let closure = expand_metadata_closure(metadata, resolve, target.as_str(), host_triple);
    let features_of = &closure.features;
    let depends_on = &closure.depends_on;
    let mut tasks = Vec::new();
    for ((pkg_id, side), features) in features_of {
        let Some(package) = packages.get(pkg_id) else {
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
        let mut deps = Vec::new();
        if let Some(edges) = depends_on.get(&(*pkg_id, *side)) {
            for (dep_pkg, dep_side) in edges {
                let Some(dep_package) = packages.get(dep_pkg) else {
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
                let dep_features = features_of.get(&(*dep_pkg, *dep_side)).ok_or_else(|| {
                    stow_error!("dep {} reached but never resolved", dep_package.name)
                })?;
                deps.push(EnqueueDependency {
                    crate_name: CrateName::parse(dep_package.name.as_str())
                        .map_err(|error| stow_error!("dependency crate_name: {error}"))?,
                    version: TypedCrateVersion::new(dep_package.version.clone()),
                    features_json: features_json(dep_features)?,
                    target: match dep_side {
                        CompileSide::Host => host_target.clone(),
                        CompileSide::Target => target.clone(),
                    },
                    rustc_version: rustc_version.clone(),
                });
            }
        }
        tasks.push(EnqueueRequest {
            crate_name: CrateName::parse(package.name.as_str())
                .map_err(|error| stow_error!("crate_name: {error}"))?,
            version: TypedCrateVersion::new(package.version.clone()),
            features_json: features_json(features)?,
            target: match side {
                CompileSide::Host => host_target.clone(),
                CompileSide::Target => target.clone(),
            },
            rustc_version: rustc_version.clone(),
            downloads,
            source: EnqueueSource::CrateUpdate,
            depends_on: deps,
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

/// The `(pkg, side)` graph one target's `resolve` closure produces:
/// each reached node's feature set and the edges its declarations
/// made.
struct MetadataClosure<'a> {
    features: HashMap<(&'a PackageId, CompileSide), BTreeSet<String>>,
    depends_on: HashMap<(&'a PackageId, CompileSide), BTreeSet<(&'a PackageId, CompileSide)>>,
}

/// Feature seeds arriving on a node grow it, and the node re-expands
/// when its set does — the fixpoint ends because a package's feature
/// universe is finite.
fn expand_metadata_closure<'a>(
    metadata: &'a Metadata,
    resolve: &'a cargo_metadata::Resolve,
    target: &str,
    host_triple: &str,
) -> MetadataClosure<'a> {
    let packages: HashMap<&PackageId, &cargo_metadata::Package> = metadata
        .packages
        .iter()
        .map(|package| (&package.id, package))
        .collect();
    let nodes: HashMap<&PackageId, &cargo_metadata::Node> =
        resolve.nodes.iter().map(|node| (&node.id, node)).collect();
    let triple_for = |side| match side {
        CompileSide::Host => host_triple,
        CompileSide::Target => target,
    };

    // Roots of the walk: the manifest's package, or every workspace
    // member when the manifest is virtual — everything a consumer's
    // build hangs under starts at the target side.
    let roots: Vec<&PackageId> = resolve.root.as_ref().map_or_else(
        || metadata.workspace_members.iter().collect(),
        |root| vec![root],
    );

    let mut seeds: HashMap<(&PackageId, CompileSide), BTreeSet<String>> = HashMap::new();
    let mut features_of: HashMap<(&PackageId, CompileSide), BTreeSet<String>> = HashMap::new();
    let mut depends_on: HashMap<(&PackageId, CompileSide), BTreeSet<(&PackageId, CompileSide)>> =
        HashMap::new();
    let mut pending = VecDeque::new();
    for root in roots {
        pending.push_back((
            root,
            CompileSide::Target,
            BTreeSet::from(["default".to_owned()]),
        ));
    }
    while let Some((pkg_id, side, new_seeds)) = pending.pop_front() {
        let (Some(package), Some(node)) = (packages.get(pkg_id), nodes.get(pkg_id)) else {
            continue;
        };
        let entry = seeds.entry((pkg_id, side)).or_default();
        let mut grew = false;
        for seed in new_seeds {
            grew |= entry.insert(seed);
        }
        if !grew && features_of.contains_key(&(pkg_id, side)) {
            continue;
        }
        let optional_deps = package
            .dependencies
            .iter()
            .map(|decl| {
                (
                    decl.rename.clone().unwrap_or_else(|| decl.name.clone()),
                    decl.optional,
                )
            })
            .collect();
        let selectable = dep_graph::selectable_features(&package.features, &optional_deps);
        let features = dep_graph::resolve_features(&package.features, &selectable, entry);
        let enable = dep_graph::enabled_dependencies(&package.features, &features);
        features_of.insert((pkg_id, side), features.clone());
        let edges = depends_on.entry((pkg_id, side)).or_default();
        for dep in &node.deps {
            let Some(dep_package) = packages.get(&dep.pkg) else {
                continue;
            };
            let proc_macro = is_proc_macro(dep_package);
            // The resolve's edge exists when any platform and feature
            // combination activates the dep; each declaration on it is
            // the per-kind/per-platform unit the walk filters by side.
            for decl in package.dependencies.iter().filter(|decl| {
                decl.name == dep_package.name.as_str() && decl.source == dep_package.source
            }) {
                if decl.kind != DependencyKind::Normal && decl.kind != DependencyKind::Build {
                    continue;
                }
                let dep_side =
                    dep_graph::dep_side(side, decl.kind == DependencyKind::Build, proc_macro);
                if let Some(spec) = &decl.target
                    && !dep_graph::dep_target_matches(&spec.to_string(), triple_for(dep_side))
                {
                    continue;
                }
                let alias = decl.rename.as_deref().unwrap_or(decl.name.as_str());
                if decl.optional && !enable.enabled.contains(alias) && !features.contains(alias) {
                    continue;
                }
                edges.insert((&dep.pkg, dep_side));
                let mut dep_seeds: BTreeSet<String> = decl.features.iter().cloned().collect();
                if decl.uses_default_features {
                    dep_seeds.insert("default".to_owned());
                }
                dep_seeds.extend(
                    enable
                        .feature_seeds
                        .get(alias)
                        .into_iter()
                        .flatten()
                        .cloned(),
                );
                pending.push_back((&dep.pkg, dep_side, dep_seeds));
            }
        }
    }
    MetadataClosure {
        features: features_of,
        depends_on,
    }
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

/// Does this package declare a proc-macro lib target — the one fact
/// metadata reports directly and the crates.io index never does.
fn is_proc_macro(package: &cargo_metadata::Package) -> bool {
    package
        .targets
        .iter()
        .any(|target| target.kind.contains(&TargetKind::ProcMacro))
}

/// The resolved feature set as the wire type — sorted, deduplicated,
/// validated.
fn features_json(features: &BTreeSet<String>) -> stow_types::error::Result<FeaturesJson> {
    FeaturesJson::canonicalize(features.iter().cloned().collect())
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
    /// "dev", null}` — and `features` naming, per package, the feature
    /// names it declares in its `[features]` table (each with no items)
    /// and that its incoming edges seed. Each edge also synthesizes the
    /// dependency declaration real metadata always carries on the
    /// parent package (`name`, `kind`, `req`, no platform spec, not
    /// optional, the dep's listed features as seeds); tests needing
    /// richer declarations pass `decls` — `(package, dep)` JSON values
    /// the caller builds itself — through `decls`.
    fn metadata_with(
        packages: &[cargo_metadata::Package],
        edges: &[(&str, &str, Option<&str>)],
        features: &[(&str, &[&str])],
    ) -> Metadata {
        metadata_with_decls(packages, edges, features, &[])
    }

    fn name_of(id: &str) -> &str {
        id.split('#')
            .nth(1)
            .and_then(|rest| rest.split('@').next())
            .unwrap_or(id)
    }

    /// One test package's `dependencies` declarations — explicit
    /// `decls` win, then the package's own, else the ones `edges` and
    /// `features` synthesize.
    fn test_decls_for(
        package: &cargo_metadata::Package,
        packages: &[cargo_metadata::Package],
        edges: &[(&str, &str, Option<&str>)],
        features: &[(&str, &[&str])],
        decls: &[(&str, serde_json::Value)],
    ) -> Vec<serde_json::Value> {
        let id = package.id.repr.as_str();
        let explicit: Vec<serde_json::Value> = decls
            .iter()
            .filter(|(pkg, _)| *pkg == id)
            .map(|(_, decl)| decl.clone())
            .collect();
        if !explicit.is_empty() {
            return explicit;
        }
        if !package.dependencies.is_empty() {
            return serde_json::to_value(&package.dependencies)
                .expect("serialize test decls")
                .as_array()
                .expect("dependencies is an array")
                .clone();
        }
        edges
            .iter()
            .filter(|(from, _, _)| *from == id)
            .map(|(_, to, kind)| {
                let dep_package = packages.iter().find(|package| package.id.repr == *to);
                let source = dep_package
                    .and_then(|package| package.source.as_ref())
                    .map(|source| source.repr.clone());
                let seeds: Vec<&str> = features
                    .iter()
                    .find(|(node, _)| *node == *to)
                    .map_or_else(Vec::new, |(_, list)| list.to_vec());
                serde_json::json!({
                    "name": name_of(to),
                    "source": source,
                    "req": "*",
                    "kind": kind,
                    "optional": false,
                    "uses_default_features": false,
                    "features": seeds,
                    "target": null,
                    "rename": null,
                    "registry": null,
                    "path": null,
                    "inherited": false,
                })
            })
            .collect()
    }

    /// `metadata_with` with explicit per-package dependency
    /// declarations: `decls` is `(package id, declaration JSON)`.
    fn metadata_with_decls(
        packages: &[cargo_metadata::Package],
        edges: &[(&str, &str, Option<&str>)],
        features: &[(&str, &[&str])],
        decls: &[(&str, serde_json::Value)],
    ) -> Metadata {
        let mut packages_json: Vec<serde_json::Value> = Vec::new();
        for package in packages {
            let mut value = serde_json::to_value(package).expect("serialize test package");
            value["dependencies"] =
                serde_json::json!(test_decls_for(package, packages, edges, features, decls));
            let declared: serde_json::Map<String, serde_json::Value> = features
                .iter()
                .find(|(node, _)| *node == package.id.repr)
                .map_or_else(serde_json::Map::new, |(_, list)| {
                    list.iter()
                        .map(|feature| ((*feature).to_owned(), serde_json::json!([])))
                        .collect()
                });
            if !declared.is_empty() {
                value["features"] = serde_json::json!(declared);
            }
            packages_json.push(value);
        }
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
                            "name": name_of(to),
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
            "packages": packages_json,
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

    /// A package whose `dependencies`/`features`/`targets` are spelled
    /// out in full — for graphs where the declarations and feature
    /// items themselves are under test.
    fn declared_package(
        name: &str,
        version: &str,
        source: Option<&str>,
        kind: &str,
        dependencies: &serde_json::Value,
        features: &serde_json::Value,
    ) -> cargo_metadata::Package {
        serde_json::from_value(serde_json::json!({
            "name": name,
            "version": version,
            "id": format!("pkg#{name}@{version}"),
            "source": source,
            "edition": "2021",
            "authors": [],
            "dependencies": dependencies,
            "features": features,
            "manifest_path": format!("/registry/{name}-{version}/Cargo.toml"),
            "targets": [{
                "kind": [kind],
                "crate_types": [kind],
                "name": name,
                "src_path": format!("/registry/{name}-{version}/src/lib.rs"),
                "edition": "2021",
            }],
        }))
        .expect("deserialize test package")
    }

    /// A `package.dependencies` entry as `cargo metadata` emits it.
    fn decl(
        name: &str,
        source: Option<&str>,
        kind: Option<&str>,
        optional: bool,
        features: &[&str],
        target: Option<&str>,
    ) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "source": source,
            "req": "*",
            "kind": kind,
            "optional": optional,
            "uses_default_features": true,
            "features": features,
            "target": target,
            "rename": null,
            "registry": null,
            "path": null,
            "inherited": false,
        })
    }

    /// The issue-317 contract end to end on a cross build: a wasm32
    /// consumer whose `serde` derives — the proc-macro package and its
    /// whole subgraph, and a `cfg(unix)`-gated build dependency
    /// evaluated against the side it compiles for, all land on the host
    /// triple, and the consumer's edge points at the host node. A
    /// `cfg(windows)` normal dependency drops out on the target side
    /// instead.
    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the metadata fixture and assertions are the contract's steps"
    )]
    fn cross_target_proc_macro_units_key_on_the_host_triple() {
        let registry = Some("registry+https://github.com/rust-lang/crates.io-index");
        let packages = vec![
            declared_package(
                "app",
                "1.0.0",
                None,
                "lib",
                &serde_json::json!([decl("serde", registry, None, false, &["derive"], None)]),
                &serde_json::json!({}),
            ),
            declared_package(
                "serde",
                "1.0.0",
                registry,
                "lib",
                &serde_json::json!([
                    decl("serde_derive", registry, None, true, &[], None),
                    decl("win-dep", registry, None, false, &[], Some("cfg(windows)")),
                    decl(
                        "host-tool",
                        registry,
                        Some("build"),
                        false,
                        &[],
                        Some("cfg(unix)")
                    ),
                ]),
                &serde_json::json!({"derive": ["dep:serde_derive"], "std": []}),
            ),
            declared_package(
                "serde_derive",
                "1.0.0",
                registry,
                "proc-macro",
                &serde_json::json!([decl(
                    "proc-macro2",
                    registry,
                    None,
                    false,
                    &["proc-macro"],
                    None,
                )]),
                &serde_json::json!({}),
            ),
            declared_package(
                "proc-macro2",
                "1.0.0",
                registry,
                "lib",
                &serde_json::json!([]),
                &serde_json::json!({"proc-macro": []}),
            ),
            declared_package(
                "win-dep",
                "1.0.0",
                registry,
                "lib",
                &serde_json::json!([]),
                &serde_json::json!({}),
            ),
            declared_package(
                "host-tool",
                "1.0.0",
                registry,
                "lib",
                &serde_json::json!([]),
                &serde_json::json!({}),
            ),
        ];
        let app = packages[0].id.repr.clone();
        let serde = packages[1].id.repr.clone();
        let serde_derive = packages[2].id.repr.clone();
        let proc_macro2 = packages[3].id.repr.clone();
        let win_dep = packages[4].id.repr.clone();
        let host_tool = packages[5].id.repr.clone();
        let metadata = metadata_with_decls(
            &packages,
            &[
                (&app, &serde, Some("normal")),
                (&serde, &serde_derive, Some("normal")),
                (&serde, &win_dep, Some("normal")),
                (&serde, &host_tool, Some("build")),
                (&serde_derive, &proc_macro2, Some("normal")),
            ],
            &[],
            &[],
        );
        let wasm = TargetTriple::parse("wasm32-unknown-unknown").unwrap();
        let tasks = tasks_from_metadata(&metadata, &wasm, &rustc(), 0).unwrap();
        let ids = task_ids(&tasks);
        let host = "x86_64-unknown-linux-gnu";
        assert_eq!(
            ids,
            BTreeSet::from([
                "serde 1.0.0 [\"derive\"] wasm32-unknown-unknown".to_string(),
                format!("serde_derive 1.0.0 [] {host}"),
                format!("proc-macro2 1.0.0 [\"proc-macro\"] {host}"),
                format!("host-tool 1.0.0 [] {host}"),
            ]),
            "win-dep is gated to a triple that matches neither side"
        );
        let serde_task = tasks
            .iter()
            .find(|task| task.crate_name.as_str() == "serde")
            .unwrap();
        let dep_targets: BTreeSet<(String, String)> = serde_task
            .depends_on
            .iter()
            .map(|dep| {
                (
                    dep.crate_name.as_str().to_owned(),
                    dep.target.as_str().to_owned(),
                )
            })
            .collect();
        assert_eq!(
            dep_targets,
            BTreeSet::from([
                ("serde_derive".to_owned(), host.to_owned()),
                ("host-tool".to_owned(), host.to_owned()),
            ]),
            "the dependent's edges point at the host nodes"
        );
        let serde_derive_task = tasks
            .iter()
            .find(|task| task.crate_name.as_str() == "serde_derive")
            .unwrap();
        assert_eq!(
            serde_derive_task
                .depends_on
                .iter()
                .map(|dep| (dep.crate_name.as_str(), dep.target.as_str()))
                .collect::<Vec<_>>(),
            [("proc-macro2", host)]
        );
    }

    /// A listed entry that still passes stays in its slot.
    #[test]
    fn merge_keeps_an_admitted_entry() {
        let verdicts = vec![
            (
                "https://github.com/a/one".to_owned(),
                ListedVerdict::Admitted,
            ),
            (
                "https://github.com/b/two".to_owned(),
                ListedVerdict::Admitted,
            ),
        ];
        assert_eq!(
            merge_listed(&verdicts, &[]),
            ["https://github.com/a/one", "https://github.com/b/two"]
        );
    }

    /// A listed entry the rule now rejects drops out — its reason is
    /// reported alongside the verdict by the caller.
    #[test]
    fn merge_drops_a_rejected_entry() {
        let verdicts = vec![
            (
                "https://github.com/a/one".to_owned(),
                ListedVerdict::Admitted,
            ),
            (
                "https://github.com/b/two".to_owned(),
                ListedVerdict::Rejected,
            ),
            (
                "https://github.com/c/three".to_owned(),
                ListedVerdict::Admitted,
            ),
        ];
        assert_eq!(
            merge_listed(&verdicts, &[]),
            ["https://github.com/a/one", "https://github.com/c/three"]
        );
    }

    /// A listed entry the rule never evaluated stays: a transport
    /// failure says nothing about the repository.
    #[test]
    fn merge_keeps_an_unevaluated_entry() {
        let verdicts = vec![
            (
                "https://github.com/a/one".to_owned(),
                ListedVerdict::NotEvaluated,
            ),
            (
                "https://github.com/b/two".to_owned(),
                ListedVerdict::Admitted,
            ),
        ];
        assert_eq!(
            merge_listed(&verdicts, &[]),
            ["https://github.com/a/one", "https://github.com/b/two"]
        );
    }

    /// Newly admitted sweep candidates append after the kept entries,
    /// in sweep order.
    #[test]
    fn merge_appends_new_admissions_after_the_kept_entries() {
        let verdicts = vec![
            (
                "https://github.com/a/one".to_owned(),
                ListedVerdict::Admitted,
            ),
            (
                "https://github.com/b/two".to_owned(),
                ListedVerdict::Rejected,
            ),
        ];
        let admitted = vec![
            "https://github.com/c/three".to_owned(),
            "https://github.com/d/four".to_owned(),
        ];
        assert_eq!(
            merge_listed(&verdicts, &admitted),
            [
                "https://github.com/a/one",
                "https://github.com/c/three",
                "https://github.com/d/four",
            ]
        );
    }

    /// A repository is one entry however many lists name it: a listed
    /// entry duplicated in the file or returned by the sweep lands once.
    #[test]
    fn merge_does_not_double_a_duplicate() {
        let verdicts = vec![
            (
                "https://github.com/a/one".to_owned(),
                ListedVerdict::Admitted,
            ),
            (
                "https://github.com/a/one".to_owned(),
                ListedVerdict::Admitted,
            ),
            (
                "https://github.com/b/two".to_owned(),
                ListedVerdict::Admitted,
            ),
        ];
        let admitted = vec![
            "https://github.com/b/two".to_owned(),
            "https://github.com/c/three".to_owned(),
        ];
        assert_eq!(
            merge_listed(&verdicts, &admitted),
            [
                "https://github.com/a/one",
                "https://github.com/b/two",
                "https://github.com/c/three",
            ]
        );
    }
}
