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
//! `submit` turns each listed repository into ordinary crate tasks by
//! asking the edge to resolve it: the checkout's committed lockfile is
//! dropped so cargo re-resolves to the latest semver-compatible
//! versions, the resolver runs once per CI target, and every crates.io
//! node in the resolve is enqueued at its resolved feature set with its
//! crates.io dependencies as `depends_on` edges at the same
//! `(target, rustc_version)`. A repository that fails to resolve is
//! reported and skipped — one bad manifest must not sink the wave.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use futures_util::{StreamExt, stream};
use stow_types::api::{EnqueueRequest, SchedulerSubmitResponse};
use stow_types::identity::{TargetTriple, WireRustcVersion};
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
    /// Why resolution failed — fetch, manifest, or resolver.
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
    /// Repositories that resolved but whose submit POST failed — a
    /// different fault than a resolve skip, reported separately.
    /// Always empty in a dry run, which submits nothing.
    submit_failed: Vec<SkippedRepo>,
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
/// The header comment `generate` writes above the `[[project]]` rows —
/// the schema's only documentation lives in the file itself.
const PROJECTS_HEADER: &str = "\
# Reviewed GitHub repositories the projects preheat lane resolves into
# crate tasks. For each entry the edge fetches the tree, drops the
# committed Cargo.lock, and resolves it once
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

/// `preheat projects submit` — resolve the list, render the plan, and
/// under `--yes` apply it repository by repository: each repository's
/// tasks post to the scheduler right after it resolves, so a token or
/// network failure mid-lane costs the wave only the repositories it
/// never reached, never the work it already did.
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
    let mut plan = ProjectsPlan {
        file: args.file.display().to_string(),
        tasks: Vec::new(),
        per_repo: Vec::with_capacity(repos.len()),
        skipped: Vec::new(),
        submit_failed: Vec::new(),
    };
    let mut outcome = SubmitOutcome {
        batches: 0,
        submitted: 0,
        inserted: 0,
        dropped: 0,
    };
    for repo in &repos {
        match resolve_repository(edge, repo, &targets, &rustc_version).await {
            Ok(tasks) => {
                tracing::info!(%repo, tasks = tasks.len(), "resolved");
                if args.yes && !tasks.is_empty() {
                    match submit_chunked(edge, &tasks).await {
                        Ok(chunk_outcome) => {
                            outcome.batches += chunk_outcome.batches;
                            outcome.submitted += chunk_outcome.submitted;
                            outcome.inserted += chunk_outcome.inserted;
                            outcome.dropped += chunk_outcome.dropped;
                        }
                        Err(error) => {
                            tracing::warn!(%repo, %error, "resolved tasks failed to submit");
                            plan.submit_failed.push(SkippedRepo {
                                repo: repo.clone(),
                                reason: format!("submit failed: {error}"),
                            });
                        }
                    }
                }
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
    }
    let envelope = render::Planned {
        dry_run: !args.yes,
        plan,
        result: args.yes.then_some(outcome),
    };
    render::emit(output, &envelope, render_projects_plan)
}

/// The human render of a projects-lane run: the resolved/skipped
/// counts, the per-repository task table, every remaining skip with its
/// reason, and — under `--yes` — the submit totals plus any repository
/// whose resolved batch failed to post.
fn render_projects_plan(envelope: &render::Planned<ProjectsPlan, SubmitOutcome>) -> String {
    let plan = &envelope.plan;
    let mut out = format!(
        "{} task(s) from {} repositories\nresolved {}, skipped {}",
        plan.tasks.len(),
        plan.per_repo.len(),
        plan.per_repo.len(),
        plan.skipped.len(),
    );
    if !plan.per_repo.is_empty() {
        let mut table = Table::new(&["repository", "tasks"]);
        for contribution in &plan.per_repo {
            table.push([contribution.repo.clone(), contribution.tasks.to_string()]);
        }
        let _ = write!(out, "\n{}", table.render());
    }
    if !plan.skipped.is_empty() {
        let mut table = Table::new(&["repository", "reason"]);
        for skipped in &plan.skipped {
            table.push([skipped.repo.clone(), skipped.reason.clone()]);
        }
        let _ = write!(out, "\nskipped\n{}", table.render());
    }
    if !plan.submit_failed.is_empty() {
        let mut table = Table::new(&["repository", "reason"]);
        for failed in &plan.submit_failed {
            table.push([failed.repo.clone(), failed.reason.clone()]);
        }
        let _ = write!(out, "\nsubmit failed\n{}", table.render());
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

/// Resolve one listed repository into its enqueue batch — `POST
/// /api/v1/admin/resolve/project` has the edge fetch the repository's
/// codeload tarball and run cargo's own resolver on it, once per CI
/// target: the committed lockfile's pins are dropped so the resolve
/// lands on the latest semver-compatible version — a project
/// contributes crate names and feature sets, never version pins.
async fn resolve_repository(
    edge: &Edge,
    repo: &str,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<Vec<EnqueueRequest>> {
    let full_name = repo.trim_start_matches("https://github.com/");
    let request = stow_types::api::AdminResolveProjectRequest {
        repo: full_name.to_owned(),
        git_ref: "HEAD".to_owned(),
        targets: targets.to_vec(),
        rustc_version: rustc_version.clone(),
        downloads: 0,
    };
    let resolved: stow_types::api::AdminResolveResponse = edge
        .post_json("/api/v1/admin/resolve/project", &request)
        .await?;
    Ok(resolved
        .targets
        .into_iter()
        .flat_map(|batch| batch.tasks)
        .collect())
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
