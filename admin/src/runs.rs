//! `stow-admin runs failures --since <duration>` — fetch failed
//! `build-crate.yml` runs from GitHub Actions, classify each run's
//! jobs page, pull the failed job's log, classify the failure, and
//! group by class.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use clap::{Args, Subcommand};
use stow_types::runs::{RunFailure, RunJobRow, RunJobsPage, classify_failure};
use stow_types::stow_error;
use stow_types::transient::Backoff;
use time::OffsetDateTime;

use crate::github::{self, BUILD_WORKFLOW};
use crate::render::{self, Output, Table};

#[derive(Args)]
pub struct RunsArgs {
    #[command(subcommand)]
    pub command: RunsCommand,
}

#[derive(Subcommand)]
pub enum RunsCommand {
    /// List failed build-crate runs in the window, grouped by the
    /// failure class their job logs show.
    Failures(FailuresArgs),
}

#[derive(Args)]
pub struct FailuresArgs {
    /// How far back to look (`30m`, `24h`, `7d`).
    #[arg(long, value_parser = parse_duration)]
    pub since: std::time::Duration,
}

fn parse_duration(raw: &str) -> Result<std::time::Duration, String> {
    humantime::parse_duration(raw).map_err(|error| format!("invalid duration `{raw}`: {error}"))
}

/// A failure class the log classifier can assign.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    /// The toolchain or runner image lacks the task's target.
    ToolchainTargetMissing,
    /// crates.io download/registry access failed.
    CratesIoDownload,
    /// A git dependency could not be fetched (the sandboxed build has no
    /// git access).
    GitDependencyOffline,
    /// The trusted publish job's plan validation refused the build
    /// output.
    PlanValidation,
    /// The runner died or setup failed before `stow-build` ever ran.
    WrapperNeverExecuted,
    /// The sandboxed build could not link: rustc found no usable linker,
    /// or the one it found refused to run.
    LinkerUnusable,
    /// The crate's own source does not compile on the task's toolchain —
    /// a rustc diagnostic with an error code, which no retry can clear.
    SourceRejected,
    /// No known class matched the log.
    Unknown,
}

impl FailureClass {
    /// Stable string form for the table view.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ToolchainTargetMissing => "toolchain-target-missing",
            Self::CratesIoDownload => "crates-io-download",
            Self::GitDependencyOffline => "git-dependency-offline",
            Self::PlanValidation => "plan-validation",
            Self::WrapperNeverExecuted => "wrapper-never-executed",
            Self::LinkerUnusable => "linker-unusable",
            Self::SourceRejected => "source-rejected",
            Self::Unknown => "unknown",
        }
    }
}

/// The class one error line belongs to, when it matches a known class.
/// Matchers run in the spec's order: toolchain → crates.io → git →
/// plan. The first error line that classifies wins the run.
fn class_of(line: &str) -> Option<FailureClass> {
    // rustup/cargo language for a target the toolchain does not carry.
    if line.contains("does not support target")
        || line.contains("does not contain target")
        || line.contains("may not be installed")
        || line.contains("target may not be downloaded")
        || line.contains("can't find crate for `std`")
    {
        return Some(FailureClass::ToolchainTargetMissing);
    }
    // A git source failing inside the sandboxed build — checked before the
    // crates.io patterns because cargo wraps both under "failed to get …
    // as a dependency".
    if line.contains("failed to load source for dependency")
        || (line.contains("Unable to update") && line.contains(".git"))
        || (line.contains("failed to update") && line.contains(".git"))
        || line.contains("failed to clone")
        || line.contains("attempted to make an HTTP request, but --offline")
    {
        return Some(FailureClass::GitDependencyOffline);
    }
    // crates.io fetch/registry failures.
    if line.contains("failed to download")
        || line.contains("unable to update registry")
        || (line.contains("failed to get") && line.contains("as a dependency"))
        || line.contains("failed to fetch `https://crates.io")
        || line.contains("failed to fetch `https://index.crates.io")
    {
        return Some(FailureClass::CratesIoDownload);
    }
    // A linker that is missing, or present and unable to run. This is what
    // 316 of 320 failed runs in one preheat wave were classified `unknown`:
    // rustc could not find MSVC's `link.exe` inside the sandbox, fell back
    // to Git for Windows' msys `link`, and that binary cannot start inside
    // an AppContainer at all.
    if line.contains("linking with")
        || line.contains("linker `")
        || line.contains("returned an unexpected error")
        || line.contains("error: linker")
    {
        return Some(FailureClass::LinkerUnusable);
    }
    // rustc's own diagnostics carry an error code; cargo's `could not
    // compile … due to N previous error(s)` summary stands in for the
    // diagnostics that do not — a `compile_error!` is a bare `error:`
    // line (stow#870). A linker failure reports its own line first, so
    // a `could not compile` that follows it never reaches this matcher.
    // An old crate that no longer compiles on the task's toolchain is a
    // permanent answer, not a transient one, so it is worth separating
    // from `unknown`.
    if line.starts_with("error[E") || line.contains("could not compile") {
        return Some(FailureClass::SourceRejected);
    }
    // ci/src/validate.rs refusals and plan.rs's planner errors.
    if line.contains("planned artifact")
        || line.contains("build output was produced for task")
        || line.contains("resolved closure")
        || line.contains("plan has no build-phase artifact")
        || line.contains("plan contains two artifacts")
        || line.contains("validate plan")
    {
        return Some(FailureClass::PlanValidation);
    }
    None
}

/// One log line with the timestamp the jobs-log API prefixes every line
/// with removed.
///
/// Every line the API serves starts with `2026-09-22T00:15:28.1515070Z `,
/// and [`is_error_line`] tests how a line *starts*, so without this the
/// only lines that ever reached a matcher were GitHub's own `##[error]`
/// annotations — which say `Process completed with exit code 1` and name
/// no cause. 493 of 498 failed runs in a six-hour window came back
/// `unknown` while every one of them carried a rustc linker error one
/// line above.
fn without_log_timestamp(line: &str) -> &str {
    let Some((stamp, rest)) = line.split_once(' ') else {
        return line;
    };
    let bytes = stamp.as_bytes();
    let is_timestamp = stamp.len() >= 20
        && stamp.ends_with('Z')
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-';
    if is_timestamp { rest } else { line }
}

/// One log line reduced to what a matcher should read: colour escapes
/// removed, then every leading timestamp removed.
///
/// A line can carry two timestamps. GitHub prefixes every line the jobs-log
/// API serves, and the wrapper's own `tracing` output opens with a second
/// one — wrapped in ANSI dim, so stripping timestamps without stripping
/// colour first leaves the escape sequence at the front and the line looks
/// like nothing at all.
fn log_line_body(line: &str) -> String {
    let plain = strip_ansi_escapes::strip_str(line);
    let mut rest = plain.as_str();
    loop {
        let stripped = without_log_timestamp(rest);
        if stripped == rest {
            break;
        }
        rest = stripped;
    }
    rest.to_owned()
}

/// Whether a log line reads as an error: GitHub's `##[error]` annotation,
/// or a leading `error`/`ERROR` from rustc, cargo, `tracing` or
/// `stow-build`'s own fatal line.
///
/// The case matters. `stow-build` ends on `Error: Error(Message(…))` and
/// its `tracing` layer prints `ERROR`, and a lowercase-only prefix test
/// read neither: 89 of 291 failed runs in one three-hour window came back
/// `unknown` while every one of them named a plan-validation refusal on a
/// line this test had skipped.
fn is_error_line(line: &str) -> bool {
    line.contains("##[error]")
        || line.contains("::error::")
        || line
            .trim_start()
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("error"))
}

/// Classify one job log. Scans error lines top-down for a known class;
/// when none match, a run whose log never shows a wrapper step's
/// `stow-build build|publish` command died before the wrapper
/// executed — the runner-loss and setup-failure bucket. `watchdog`
/// reuses it for the incident's failure-class breakdown.
pub fn classify_log(log: &str) -> (FailureClass, Option<String>) {
    for line in log.lines() {
        let line = log_line_body(line);
        let line = line.as_str();
        if !is_error_line(line) {
            continue;
        }
        if line.contains("lost communication")
            || line.contains("shutdown signal")
            || line.contains("operation was canceled")
        {
            return (
                FailureClass::WrapperNeverExecuted,
                Some(line.trim().to_owned()),
            );
        }
        if let Some(class) = class_of(line) {
            return (class, Some(line.trim().to_owned()));
        }
    }
    // The workflow's banner for the two wrapper steps
    // (build-crate.yml): the untrusted build's multi-line script echoes
    // `stow-build build --output-dir …` inside its `##[group]Run` block,
    // and the trusted publish's single-line `run:` is
    // `##[group]Run stow-build publish --input-dir …`. The subcommand
    // flags pin the match to the step commands — a bare `stow-build`
    // substring also matches the stow-toolchain action's download
    // chatter, which runs before the wrapper ever starts (stow#870).
    if !(log.contains("stow-build build --") || log.contains("stow-build publish --")) {
        return (FailureClass::WrapperNeverExecuted, None);
    }
    (FailureClass::Unknown, None)
}

/// The first line [`is_error_line`] accepts, reduced by
/// [`log_line_body`] — the digest's per-failure evidence line.
pub fn first_error_line(log: &str) -> Option<String> {
    log.lines()
        .map(log_line_body)
        .find(|line| is_error_line(line))
        .map(|line| line.trim().to_owned())
}

/// The job whose log classifies a failed run — the row the
/// `jobs/{id}/logs` read asks for, `None` when the failure names no
/// the evidence, there is no log) or a named job absent from the page.
/// Shared by `runs failures` and the watch: the watch keys its
/// `log_class` memo on the returned row's id, so the row must be named
/// before any fetch is decided (stow#853).
pub fn failure_log_job<'a>(failure: &TaskFailure, jobs: &'a [RunJobRow]) -> Option<&'a RunJobRow> {
    jobs.iter().find(|row| row.name == *failure_job(failure))
}

/// The job a task failure names — `"-"` when it names no job row.
const fn failure_job(failure: &TaskFailure) -> &String {
    match failure {
        TaskFailure::Run(
            RunFailure::Verdict { job, .. } | RunFailure::Infrastructure { job, .. },
        )
        | TaskFailure::Concluded { job, .. } => job,
    }
}

/// `(failure, log)` → `(job_name, class, evidence)` — the shared
/// failure read `runs failures` and the watch make. `log` is the named
/// job's log when the caller read it: an absent or unreadable log
/// reads [`FailureClass::Unknown`] with none, anything else is
/// [`classify_log`]'s answer. `job_name` is the report's display name —
/// `"-"` for the case that names no job.
pub fn failure_class_of(
    failure: &TaskFailure,
    log: Option<&str>,
) -> (String, FailureClass, Option<String>) {
    let job = failure_job(failure).clone();
    let (class, evidence) = log.map_or((FailureClass::Unknown, None), classify_log);
    (job, class, evidence)
}

// ===== Run classification =====
//
// `VERDICT_STEPS`, `STEP_SETTLE_WINDOW`, `RunFailure`,
// `classify_failure` and the jobs-page row types live in
// `stow_types::runs` — the edge's watchdog runs the same contract.
// `classify_log` and its `FailureClass` stay here: they read job
// logs, which only `runs failures`, `builds digest` and `watchdog`
// pull.

/// A task's failure — a classified [`RunFailure`], or the plain
/// conclusion a cancelled or skipped run leaves without any job to
/// classify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskFailure {
    /// `classify_failure`'s verdict.
    Run(RunFailure),
    /// The task's job concluded without a failure — an operator
    /// cancel, `skipped` collateral or a `timed_out` runner.
    Concluded {
        /// The task's build job's name, or `"-"` when no build row
        /// ever landed.
        job: String,
        /// The conclusion the job carried — `cancelled`, `skipped`,
        /// `timed_out`, …
        conclusion: String,
    },
}

/// Where a run's task settled — `classify_failure`'s answer plus the
/// conclusions that need no page (stow#853).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskOutcome {
    /// The run's jobs are done and none failed.
    Succeeded,
    /// The run's task failed — the failure rides.
    Failed(TaskFailure),
    /// The page is still writing or the run has not finished — the
    /// caller repolls.
    Unsettled,
}

/// Classify a `build-crate.yml` run's jobs page — one task per run.
///
/// A `failure`-concluded run reads `classify_failure`'s answer:
/// `Some` settles the task failed, `None` (a page still writing, or
/// an unsettled job inside the settle window) defers. A completed
/// `success` run's page is all-success — `Succeeded`. A terminal
/// conclusion that is neither — `cancelled`, `skipped`,
/// `timed_out` — is a `Concluded` failure the reports read as
/// collateral, not an attempted build. Anything else is `Unsettled`:
/// the run is still in flight.
pub fn classify_page(
    jobs: &[RunJobRow],
    run_conclusion: &str,
    now: OffsetDateTime,
) -> stow_types::error::Result<TaskOutcome> {
    match run_conclusion {
        "success" => Ok(TaskOutcome::Succeeded),
        "failure" => Ok(
            classify_failure(jobs, now)?.map_or(TaskOutcome::Unsettled, |failure| {
                TaskOutcome::Failed(TaskFailure::Run(failure))
            }),
        ),
        "" | "queued" | "in_progress" | "waiting" | "requested" | "pending" => {
            Ok(TaskOutcome::Unsettled)
        }
        conclusion => {
            let job = build_job(jobs);
            Ok(TaskOutcome::Failed(TaskFailure::Concluded {
                job: job.map_or_else(|| "-".to_owned(), |row| row.name.clone()),
                conclusion: job
                    .and_then(|row| row.conclusion.as_deref())
                    .unwrap_or(conclusion)
                    .to_owned(),
            }))
        }
    }
}

/// Whether a failed run's task was actually attempted — a `Concluded`
/// `cancelled`/`skipped` is an operator's cancel or collateral, never
/// a failed build the reports count.
pub fn attempted(failure: &TaskFailure) -> bool {
    !matches!(failure, TaskFailure::Concluded { conclusion, .. } if matches!(conclusion.as_str(), "cancelled" | "skipped"))
}

/// What a task's `build` job name carries — the digest's grouping
/// keys and the watchdog's target evidence. `build-crate.yml` writes
/// it as `build <crate> <version> (<target>)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskLabel {
    /// Crate name as known to crates.io.
    pub crate_name: String,
    /// Exact crate version.
    pub version: String,
    /// Compilation target triple — carried verbatim in the job name.
    pub target: String,
}

/// Parse a `build` job's name back into its label — the job names the
/// crate, version and target; `None` on a name that is not a `build`
/// job's or whose label does not match (the callers fail fast on it:
/// the run is ours, so an unreadable label is a schema surprise).
pub fn task_label(job_name: &str) -> Option<TaskLabel> {
    let label = job_name.strip_prefix("build ")?;
    let (name_version, target) = label.rsplit_once(" (")?;
    let target = target.strip_suffix(')')?;
    let (crate_name, version) = name_version.split_once(' ')?;
    if crate_name.is_empty() || semver::Version::parse(version).is_err() || target.is_empty() {
        return None;
    }
    Some(TaskLabel {
        crate_name: crate_name.to_owned(),
        version: version.to_owned(),
        target: target.to_owned(),
    })
}

/// The run's `build` job row on the page — its name is the label
/// source and its id the log path.
pub fn build_job(jobs: &[RunJobRow]) -> Option<&RunJobRow> {
    jobs.iter().find(|job| job.name.starts_with("build "))
}

/// Where a live run's task is — the watch's split of
/// `classify_page`'s `Unsettled` plus its two settled answers
/// (stow#853). Only the watch reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskProgress {
    /// The build job waits for a runner.
    Queued,
    /// The build job is running.
    Building,
    /// The build job is done `success`; the publish job has not
    /// landed or has not concluded.
    Publishing,
    /// A `failure` row's verdict is still undecided — its step rows
    /// inside `STEP_SETTLE_WINDOW` or a sibling row still writing.
    Settling,
    /// `classify_page` settled the run `Succeeded`.
    Done,
    /// `classify_page` settled the run failed — the failure rides.
    Failed(TaskFailure),
}

/// One `build-crate.yml` run's live task — the watch's row.
#[derive(Debug, Clone)]
pub struct LiveTask {
    /// Where the task is.
    pub progress: TaskProgress,
    /// Crate, version and target from the build job's name — `None`
    /// while the build job has not landed.
    pub label: Option<TaskLabel>,
}

/// `classify_page` with `Unsettled` split into live progress — the
/// watch's per-task truth. `Succeeded` and `Failed` carry through; an
/// `Unsettled` run names where its task stands: waiting on a runner
/// ([`TaskProgress::Queued`]), running ([`TaskProgress::Building`]),
/// build done and publish pending ([`TaskProgress::Publishing`]), or
/// still writing a failure ([`TaskProgress::Settling`]).
///
/// # Errors
/// An `Unsettled` run whose build row reports a status the table
/// does not name — a schema surprise, never a bucket.
pub fn live_task(
    jobs: &[RunJobRow],
    run_conclusion: &str,
    now: OffsetDateTime,
) -> stow_types::error::Result<LiveTask> {
    let progress = match classify_page(jobs, run_conclusion, now)? {
        TaskOutcome::Succeeded => TaskProgress::Done,
        TaskOutcome::Failed(failure) => TaskProgress::Failed(failure),
        TaskOutcome::Unsettled => task_progress(jobs)?,
    };
    let label = build_job(jobs).and_then(|job| task_label(&job.name));
    Ok(LiveTask { progress, label })
}

/// One `Unsettled` run's progress from its rows. Any `failure`
/// conclusion is the verdict still settling — `classify_failure`
/// defers on unsettled step rows inside their window and on a
/// sibling job still writing, and both leave the task undecided.
/// Otherwise the build row says where the task is, conclusion over
/// status: a build row carrying `success` is past the build stage
/// whatever its `status` still says (stow#863), and `Unsettled` then
/// means the publish row is absent or still running — `Publishing`.
fn task_progress(jobs: &[RunJobRow]) -> stow_types::error::Result<TaskProgress> {
    if jobs
        .iter()
        .any(|job| job.conclusion.as_deref() == Some("failure"))
    {
        return Ok(TaskProgress::Settling);
    }
    let Some(build) = build_job(jobs) else {
        // The run landed but its build job has not — GitHub serves
        // an empty page while the run queues.
        return Ok(TaskProgress::Queued);
    };
    if build.conclusion.as_deref() == Some("success") {
        return Ok(TaskProgress::Publishing);
    }
    Ok(match build.status.as_str() {
        "queued" | "waiting" | "pending" | "requested" => TaskProgress::Queued,
        "in_progress" => TaskProgress::Building,
        // `completed` without a `conclusion` yet — the row is still
        // being written, so the task is undecided.
        "completed" => TaskProgress::Settling,
        status => {
            return Err(stow_error!(
                "unsettled run's build job {:?} reports status {status}",
                build.name
            ));
        }
    })
}

/// Every job row of a run's attempt — the whole list, not one page
/// (stow#833).
///
/// The attempt is pinned: the default `filter=latest` jobs view
/// (`GET …/runs/{id}/jobs`) answers 502 on every request for a run
/// whose failed task was rerun, while the attempt-scoped view serves
/// the same rows (stow#852). The edge's `attempt_jobs_path` reads the
/// same path.
///
/// A run carries at most two jobs, but the pager still follows the
/// RFC 8288 `Link` header's
/// `rel="next"` (`stow_types::runs::link_next`, the same parse the
/// edge's `attempt_jobs` runs) until GitHub names no next page.
/// `runs failures`, `builds digest`, the watchdog and the preheat
/// driver all read their jobs through here — the one pager, nowhere
/// duplicated.
pub async fn fetch_run_jobs(
    token: &str,
    run_id: u64,
    attempt: u64,
) -> stow_types::error::Result<Vec<RunJobRow>> {
    fetch_attempt_jobs(
        Some(token),
        github::API_BASE,
        run_id,
        attempt,
        None,
        Backoff::new,
    )
    .await
}

/// [`fetch_run_jobs`] at a resolved API root and under the caller's
/// retry policy — `backoff` is the fresh per-page budget factory (the
/// report readers pass [`Backoff::new`]; the preheat driver passes
/// [`Backoff::outage`], a wave holding no runner may wait an incident
/// out). `pages` is the conditional cache a repeated reader carries —
/// `None` for a one-shot read, which walks the pages through an
/// ephemeral one; a carried cache revalidates each page URL on its
/// own `ETag`, so a re-read pays a full body only for a page that
/// changed. A `Link` pointing outside the base the first page was
/// read from is refused: followed verbatim it would carry the
/// operator token to a host the API never named. `Authorization`
/// rides only when `token` is `Some` (the same convention
/// `github::send_get` holds for loopback reads).
pub async fn fetch_attempt_jobs(
    token: Option<&str>,
    base: &str,
    run_id: u64,
    attempt: u64,
    pages: Option<&mut github::ConditionalPages<RunJobsPage>>,
    backoff: fn() -> Backoff,
) -> stow_types::error::Result<Vec<RunJobRow>> {
    let mut ephemeral = github::ConditionalPages::new();
    let pages = pages.unwrap_or(&mut ephemeral);
    let mut jobs = Vec::new();
    let mut url = run_jobs_url(base, run_id, attempt);
    loop {
        let (page, next) = pages.get(token, &url, backoff()).await?;
        jobs.extend_from_slice(&page.jobs);
        let Some(next) = next else { break };
        if !next.starts_with(&format!("{base}/")) {
            return Err(stow_error!(
                "jobs page `Link` next {next} leaves {base} — refused"
            ));
        }
        url = next.to_owned();
    }
    Ok(jobs)
}

/// `GET {base}/repos/{REPO}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100`
/// — the first page the pager opens; later pages ride the `Link`
/// header's URLs verbatim.
fn run_jobs_url(base: &str, run_id: u64, attempt: u64) -> String {
    format!(
        "{base}/repos/{}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100",
        github::REPO
    )
}

// ===== GitHub REST shapes =====

/// One classified failure, for the report's example lists.
#[derive(Debug, serde::Serialize)]
struct FailureExample {
    run_url: String,
    job: String,
    /// The log line that classified the failure, when one did.
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<String>,
}

/// Per-class grouping in the report.
#[derive(Debug, serde::Serialize)]
struct FailureGroup {
    class: FailureClass,
    tasks: usize,
    examples: Vec<FailureExample>,
}

/// The `runs failures` payload.
#[derive(Debug, serde::Serialize)]
struct FailuresReport {
    workflow: &'static str,
    since_seconds: u64,
    failed_runs: usize,
    failed_tasks: usize,
    groups: Vec<FailureGroup>,
}

pub async fn run(token: &str, args: RunsArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        RunsCommand::Failures(args) => failures(token, args, output).await,
    }
}

/// Every failed run of the build workflow in the closed window
/// `[now-since, now]` — range enumeration reads the whole window past
/// GitHub's 1000-row listing cap, so a dense failure wave no longer
/// drops its tail (stow#555). Each run is one task, so the listing is
/// of the failed tasks themselves.
async fn fetch_failed_runs(
    token: &str,
    since: std::time::Duration,
) -> stow_types::error::Result<Vec<github::WorkflowRunRow>> {
    let until = time::OffsetDateTime::now_utc();
    github::runs_in_range(
        BUILD_WORKFLOW,
        "status=failure",
        until - since,
        until,
        |path| async move {
            github::get::<github::RunsPage<github::WorkflowRunRow>>(token, &path, Backoff::new())
                .await
        },
    )
    .await
}

/// Classify each failed run on its attempt's jobs page, then fetch
/// each failed run's failed-job log and group the classified failures.
async fn classify_runs(
    token: &str,
    runs: &[github::WorkflowRunRow],
) -> stow_types::error::Result<Vec<FailureGroup>> {
    let mut groups: BTreeMap<FailureClass, Vec<FailureExample>> = BTreeMap::new();
    for run in runs {
        let jobs = fetch_run_jobs(token, run.id, run.run_attempt).await?;
        let TaskOutcome::Failed(failure) =
            classify_page(&jobs, "failure", OffsetDateTime::now_utc())?
        else {
            continue;
        };
        if !attempted(&failure) {
            continue;
        }
        let (job_name, class, evidence) = match failure_log_job(&failure, &jobs) {
            Some(job) => {
                let log_url = format!(
                    "https://api.github.com/repos/{}/actions/jobs/{}/logs",
                    github::REPO,
                    job.id
                );
                match github::get_text(token, &log_url, Backoff::new()).await {
                    Ok(log) => failure_class_of(&failure, Some(&log)),
                    Err(error) => {
                        tracing::warn!(job_id = job.id, %error, "job log unavailable; skipping");
                        continue;
                    }
                }
            }
            // The failure names no log to read — anything else
            // classifies `Unknown`.
            None => failure_class_of(&failure, None),
        };
        groups.entry(class).or_default().push(FailureExample {
            run_url: run.html_url.clone(),
            job: job_name,
            evidence,
        });
    }
    Ok(groups
        .into_iter()
        .map(|(class, examples)| FailureGroup {
            class,
            tasks: examples.len(),
            examples,
        })
        .collect())
}

async fn failures(
    token: &str,
    args: FailuresArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    let runs = fetch_failed_runs(token, args.since).await?;
    let groups = classify_runs(token, &runs).await?;
    let failed_tasks = groups.iter().map(|group| group.tasks).sum();

    let report = FailuresReport {
        workflow: BUILD_WORKFLOW,
        since_seconds: args.since.as_secs(),
        failed_runs: runs.len(),
        failed_tasks,
        groups,
    };
    render::emit(output, &report, |report| {
        if report.groups.is_empty() {
            return format!(
                "no failed {} runs in the last {}",
                report.workflow,
                render::age(report.since_seconds)
            );
        }
        let mut out = format!(
            "{} failed {} run(s) in the last {}\n",
            report.failed_tasks,
            report.workflow,
            render::age(report.since_seconds)
        );
        let mut table = Table::new(&["class", "runs", "example"]);
        for group in &report.groups {
            let example = group
                .examples
                .first()
                .map_or("-", |example| example.run_url.as_str());
            table.push([
                group.class.as_str().to_owned(),
                group.tasks.to_string(),
                example.to_owned(),
            ]);
        }
        let _ = write!(out, "{}", table.render());
        for group in &report.groups {
            for example in group.examples.iter().take(3) {
                let _ = write!(
                    out,
                    "\n{}  {}  {}",
                    group.class.as_str(),
                    example.job,
                    example.run_url
                );
                if let Some(evidence) = &example.evidence {
                    let _ = write!(out, "\n    {evidence}");
                }
            }
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use stow_types::runs::RunStepRow;
    use stow_types::transient::Backoff;

    use super::{
        FailureClass, RunFailure, RunJobRow, TaskFailure, TaskOutcome, TaskProgress, attempted,
        classify_log, classify_page, failure_class_of, failure_log_job, live_task, log_line_body,
        task_label,
    };

    /// Did the classified run's task actually attempt — a cancelled or
    /// skipped collateral and a jobless `startup_failure` both read
    /// `false`, an attempted failure `true`.
    fn run_attempted(jobs: &[RunJobRow], run_conclusion: &str) -> bool {
        matches!(
            classify_page(jobs, run_conclusion, at(1_000)),
            Ok(TaskOutcome::Failed(failure)) if attempted(&failure)
        )
    }

    /// The jobs-log API stamps every line with an RFC 3339 timestamp, so a
    /// fixture without one tests a format that never arrives. This is the
    /// tail of job 35670381569's log, byte for byte.
    const WINDOWS_LINKER_LOG: &str = "2026-09-22T00:15:28.1515070Z error: linking with `link.exe` failed: exit code: 0xc0000142\n2026-09-22T00:15:28.1530117Z   = note:       0 [main] link (1084) C:\\Program Files\\Git\\usr\\bin\\link.exe: *** fatal error - NtCreateDirectoryObject(\\BaseNamedObjects\\msys-2.0S5-1888ae32e00d56aa): 0xC0000022\n2026-09-22T00:15:28.3831380Z note: `link.exe` returned an unexpected error\n2026-09-22T00:15:28.4001532Z error: could not compile `windows_i686_gnu` (build script) due to 1 previous error\n2026-09-22T00:15:28.5446466Z ##[error]Process completed with exit code 1.\n";

    #[test]
    fn classifies_a_linker_that_cannot_run() {
        // The Windows failure that made two of nine target triples produce
        // nothing, reported verbatim as the job log carried it.
        let log = "    Checking tracing v0.1.44\n                   error: linking with `link.exe` failed: exit code: 0xc0000142\n                   note: `link.exe` returned an unexpected error\n";
        assert_eq!(classify_log(log).0, FailureClass::LinkerUnusable);
    }

    /// The timestamp every line carries used to hide the cause: the only
    /// line `is_error_line` accepted was GitHub's own annotation, which
    /// names no class, so the run reported `unknown`.
    #[test]
    fn a_timestamped_log_classifies_by_its_cause_not_its_exit_code() {
        let (class, evidence) = classify_log(WINDOWS_LINKER_LOG);
        assert_eq!(class, FailureClass::LinkerUnusable);
        assert_eq!(
            evidence.as_deref(),
            Some("error: linking with `link.exe` failed: exit code: 0xc0000142")
        );
    }

    /// A tracing line carries `error=` in the middle and is not an error
    /// line; stripping the timestamp must not turn one into a match.
    #[test]
    fn a_timestamped_warning_is_not_an_error_line() {
        let log = "2026-09-22T00:10:28.9895832Z 2026-09-22T00:10:28.988844Z  WARN hyper connection error error=connection error\n2026-09-22T00:15:28.1515070Z error: failed to download `serde v1.0.0`\n";
        assert_eq!(classify_log(log).0, FailureClass::CratesIoDownload);
    }

    #[test]
    fn a_missing_target_still_wins_over_a_linker_line() {
        // A toolchain without the target reports both; the target is the
        // cause and the linker line is a consequence.
        let log = "##[error]error: toolchain '1.98.1' does not support target 'aarch64-pc-windows-msvc'\n                   error: linking with `link.exe` failed\n";
        assert_eq!(classify_log(log).0, FailureClass::ToolchainTargetMissing);
    }

    #[test]
    fn classifies_toolchain_missing_target() {
        let log = "some log\n##[error]error: toolchain '1.91.1' does not support target 'aarch64-apple-ios-sim'\n";
        let (class, evidence) = classify_log(log);
        assert_eq!(class, FailureClass::ToolchainTargetMissing);
        assert!(evidence.is_some());
    }

    /// `cc 0.0.1`, published in 2014, does not compile on rustc 1.98. No
    /// retry can change that, so it is not the `unknown` bucket.
    #[test]
    fn classifies_a_crate_whose_source_no_longer_compiles() {
        let log = "2026-09-21T23:51:54.7327653Z error[E0308]: mismatched types\n2026-09-21T23:51:54.7330807Z error: could not compile `cc` (lib) due to 10 previous errors\n";
        assert_eq!(classify_log(log).0, FailureClass::SourceRejected);
    }

    /// clircle 0.6.1's `compile_error!` on wasm32-unknown-unknown, as
    /// the real job log carried it: the diagnostic has no error code,
    /// so cargo's `could not compile` summary is the line that names
    /// the rejection (stow#870).
    const COMPILE_ERROR_LOG: &str = "2026-10-09T14:42:17.1183201Z error: Neither cfg(unix) nor cfg(windows) was true, aborting.\n2026-10-09T14:42:17.2100448Z error: could not compile `clircle` (lib) due to 1 previous error\n2026-10-09T14:42:17.5406119Z Error: Error(Message(\"cargo check failed for clircle 0.6.1 on wasm32-unknown-unknown with status exit status: 101\"))\n";

    /// A `compile_error!` rejection — no `error[E…]` line exists — is a
    /// source rejection on cargo's summary line, not `unknown`.
    #[test]
    fn a_compile_error_is_a_source_rejection() {
        let (class, evidence) = classify_log(COMPILE_ERROR_LOG);
        assert_eq!(class, FailureClass::SourceRejected);
        assert_eq!(
            evidence.as_deref(),
            Some("error: could not compile `clircle` (lib) due to 1 previous error")
        );
    }

    /// A linker failure also ends in `could not compile`; the scan
    /// reaches the linker line first, so its class still wins.
    #[test]
    fn a_linker_failure_is_not_a_source_rejection() {
        assert_eq!(
            classify_log(WINDOWS_LINKER_LOG).0,
            FailureClass::LinkerUnusable
        );
    }

    #[test]
    fn classifies_crates_io_download() {
        let log = "error: failed to download `serde v1.0.0`\n";
        assert_eq!(classify_log(log).0, FailureClass::CratesIoDownload);
    }

    #[test]
    fn classifies_git_dependency_offline() {
        let log = "error: failed to load source for dependency `waterui`\nCaused by: Unable to update https://github.com/x/y.git\n";
        assert_eq!(classify_log(log).0, FailureClass::GitDependencyOffline);
    }

    #[test]
    fn classifies_plan_validation() {
        let log = "error: planned artifact ghcr.io/x claims crate serde 1.0.0, which is not in the resolved closure of y 2.0 (3 packages)\n";
        assert_eq!(classify_log(log).0, FailureClass::PlanValidation);
    }

    /// The real publish-job tail of run 35688447309, byte for byte: a
    /// `tracing` line whose own timestamp sits inside ANSI dim behind
    /// GitHub's timestamp, then `stow-build`'s fatal line, which opens with
    /// a capital `Error:`. Every one of the 89 runs this class covered in a
    /// three-hour window came back `unknown` on these two lines.
    const PLAN_VALIDATION_LOG: &str = concat!(
        "2026-09-22T04:52:13.5343814Z \x1b[2m2026-09-22T04:52:13.534052Z\x1b[0m \x1b[31mERROR\x1b[0m ",
        "publish stage failed \x1b[3mtask_id\x1b[0m\x1b[2m=\x1b[0mcolor-spantrace-0.3.0-aarch64_unknown_linux_gnu-1.98.1 ",
        "\x1b[3merror\x1b[0m\x1b[2m=\x1b[0mplan has no build-phase artifact for log 0.4.34, ",
        "a library package in the resolved closure of color-spantrace 0.3.0\n",
        "2026-09-22T04:52:13.9332983Z Error: Error(Message(\"plan has no build-phase artifact for log 0.4.34, ",
        "a library package in the resolved closure of color-spantrace 0.3.0\"))\n",
        "2026-09-22T04:52:13.9359390Z ##[error]Process completed with exit code 1.\n",
    );

    #[test]
    fn classifies_a_publish_stage_refusal_behind_colour_and_two_timestamps() {
        let (class, line) = classify_log(PLAN_VALIDATION_LOG);
        assert_eq!(class, FailureClass::PlanValidation);
        let line = line.expect("the classified line is reported");
        assert!(
            line.starts_with("ERROR publish stage failed"),
            "both timestamps and every escape should be gone: {line}"
        );
    }

    /// `stow-build`'s own fatal line alone, with no `tracing` line above it,
    /// is enough — the capital `Error:` is what a lowercase prefix test
    /// missed.
    #[test]
    fn a_capital_error_line_is_an_error_line() {
        let log = "2026-09-22T04:52:13.9332983Z Error: Error(Message(\"plan contains two artifacts for serde 1.0.0 (compile keys a and b)\"))\n";
        assert_eq!(classify_log(log).0, FailureClass::PlanValidation);
    }

    /// A line carrying only GitHub's timestamp still loses exactly one.
    #[test]
    fn a_single_timestamp_is_stripped_once() {
        assert_eq!(
            log_line_body("2026-09-22T00:15:28.1515070Z error: linking with `link.exe` failed"),
            "error: linking with `link.exe` failed"
        );
    }

    #[test]
    fn wrapper_never_executed_when_build_step_absent() {
        // A runner-loss log may carry error lines the known classes do
        // not match; what makes it a never-executed wrapper is that no
        // `stow-build …` step banner appears at all.
        let log = "Waiting for a runner to pick up this job...\n##[error]error: something odd\n";
        assert_eq!(classify_log(log).0, FailureClass::WrapperNeverExecuted);
    }

    /// Either wrapper step's banner proves the wrapper ran — the
    /// publish stage's `##[group]Run stow-build publish …` and
    /// the build stage's `stow-build build …`, echoed on its own
    /// line inside the multi-line script's `##[group]Run` block
    /// (build-crate.yml, stow#870).
    #[test]
    fn unknown_when_wrapper_ran_but_no_pattern_matched() {
        for banner in [
            "##[group]Run stow-build publish --input-dir \"/home/runner/work/_temp/stow-build-output\"",
            "##[group]Run set -euo pipefail\nstow-build build --output-dir \"/home/runner/work/_temp/stow-build-output\"",
        ] {
            let log = format!("{banner}\n##[error]error: something odd\n");
            assert_eq!(classify_log(&log).0, FailureClass::Unknown, "{banner}");
        }
    }

    #[test]
    fn first_error_line_wins() {
        let log = "##[error]error: toolchain '1.91.1' does not support target 'x'\nerror: failed to download `y`\n";
        assert_eq!(classify_log(log).0, FailureClass::ToolchainTargetMissing);
    }

    // ----- Run classification (stow#833) -----

    fn at(unix: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(unix).expect("timestamp")
    }

    /// One job row of a `build-crate.yml` run's page — settled
    /// (`completed`) unless the fixture says otherwise.
    fn job_row(name: &str, conclusion: Option<&str>, steps: Vec<RunStepRow>) -> RunJobRow {
        RunJobRow {
            id: 0,
            name: name.to_owned(),
            status: "completed".to_owned(),
            conclusion: conclusion.map(str::to_owned),
            started_at: Some(at(50)),
            completed_at: Some(at(100)),
            run_attempt: 1,
            html_url: String::new(),
            steps,
        }
    }

    /// The build job's name as `build-crate.yml` writes it —
    /// `build <crate> <version> (<target>)`.
    fn build_name() -> &'static str {
        "build serde 1.0.0 (x86_64-unknown-linux-gnu)"
    }

    /// The publish job's name — `publish`.
    fn publish_name() -> &'static str {
        "publish"
    }

    /// The build job name's label round-trips: crate, version and the
    /// verbatim target.
    #[test]
    fn task_label_reads_crate_version_target() {
        let label = task_label("build gix-hash 0.27.0 (aarch64-pc-windows-msvc)").expect("label");
        assert_eq!(label.crate_name, "gix-hash");
        assert_eq!(label.version, "0.27.0");
        assert_eq!(label.target, "aarch64-pc-windows-msvc");
    }

    /// A publish job's name carries no label; anything off the
    /// `build <crate> <version> (<target>)` shape — a missing version,
    /// a non-semver one, a missing target — parses nothing.
    #[test]
    fn task_label_rejects_non_build_and_malformed_names() {
        for name in [
            "publish",
            "build serde (x86_64-unknown-linux-gnu)",
            "build serde not-semver (x86_64-unknown-linux-gnu)",
            "build serde 1.0.0 x86_64-unknown-linux-gnu",
            "build-crate",
        ] {
            assert_eq!(task_label(name), None, "{name}");
        }
    }

    /// A failed run's page classifies its task: a verdict step fails
    /// the run as the crate's verdict; the cancelled publish is
    /// `fail-fast` collateral.
    #[test]
    fn classify_page_reports_a_verdict_failure() {
        let jobs = vec![
            job_row(
                build_name(),
                Some("failure"),
                vec![RunStepRow {
                    name: "Run the untrusted build stage".to_owned(),
                    status: "completed".to_owned(),
                    conclusion: Some("failure".to_owned()),
                }],
            ),
            job_row(publish_name(), Some("skipped"), vec![]),
        ];
        match classify_page(&jobs, "failure", at(1_000)).expect("classified") {
            TaskOutcome::Failed(TaskFailure::Run(RunFailure::Verdict { step, .. })) => {
                assert_eq!(step, "Run the untrusted build stage");
            }
            other => panic!("the task is the crate's verdict: {other:?}"),
        }
        assert!(run_attempted(&jobs, "failure"));
    }

    /// stow#863: run 39842358378 — a `completed` run's job row served
    /// `in_progress` with `conclusion: "success"` already written. The
    /// conclusion settles the row whatever `status` says: the task
    /// reads `Succeeded` on the first read rather than repolling.
    #[test]
    fn classify_page_settles_a_run_on_its_conclusion() {
        let mut publish = job_row(publish_name(), Some("success"), vec![]);
        publish.status = "in_progress".to_owned();
        let jobs = vec![job_row(build_name(), Some("success"), vec![]), publish];
        assert_eq!(
            classify_page(&jobs, "success", at(1_000)).expect("classified"),
            TaskOutcome::Succeeded
        );
    }

    /// A cancelled run's task was never attempted — the report does
    /// not count operator collateral as a failed build.
    #[test]
    fn classify_page_marks_a_cancelled_run_not_attempted() {
        let jobs = vec![
            job_row(build_name(), Some("cancelled"), vec![]),
            job_row(publish_name(), Some("skipped"), vec![]),
        ];
        assert!(!run_attempted(&jobs, "cancelled"));
    }

    /// A run that lost its runner before any job ran — no rows, the
    /// `startup_failure` shape — classifies infrastructure.
    #[test]
    fn classify_page_a_jobless_failure_is_infrastructure() {
        match classify_page(&[], "failure", at(1_000)).expect("classified") {
            TaskOutcome::Failed(TaskFailure::Run(RunFailure::Infrastructure { job, .. })) => {
                assert_eq!(job, "-");
            }
            other => panic!("a jobless failure is infrastructure: {other:?}"),
        }
        assert!(!run_attempted(&[], "cancelled"));
    }

    // ----- Live progress (stow#853) -----

    /// One job row of a live run — `status`/`conclusion`/`completed_at`
    /// as GitHub serves them mid-write.
    fn live_job(
        name: &str,
        status: &str,
        conclusion: Option<&str>,
        completed_at: Option<i64>,
        steps: Vec<RunStepRow>,
    ) -> RunJobRow {
        RunJobRow {
            id: 0,
            name: name.to_owned(),
            status: status.to_owned(),
            conclusion: conclusion.map(str::to_owned),
            started_at: Some(at(50)),
            completed_at: completed_at.map(at),
            run_attempt: 1,
            html_url: String::new(),
            steps,
        }
    }

    fn live_step(name: &str, status: &str, conclusion: Option<&str>) -> RunStepRow {
        RunStepRow {
            name: name.to_owned(),
            status: status.to_owned(),
            conclusion: conclusion.map(str::to_owned),
        }
    }

    /// A queued build row is a queued task.
    #[test]
    fn a_queued_build_row_is_a_queued_task() {
        let jobs = vec![live_job(build_name(), "queued", None, None, vec![])];
        let task = live_task(&jobs, "in_progress", at(1_000)).expect("classified");
        assert_eq!(task.progress, TaskProgress::Queued);
        assert!(task.label.is_some());
    }

    /// An in-progress build row is a building task.
    #[test]
    fn an_in_progress_build_row_is_building() {
        let jobs = vec![live_job(build_name(), "in_progress", None, None, vec![])];
        let task = live_task(&jobs, "in_progress", at(1_000)).expect("classified");
        assert_eq!(task.progress, TaskProgress::Building);
    }

    /// A succeeded build with no publish row yet is publishing —
    /// `classify_page` cannot settle the run until the publish lands.
    #[test]
    fn a_succeeded_build_is_publishing() {
        let jobs = vec![live_job(
            build_name(),
            "completed",
            Some("success"),
            Some(100),
            vec![],
        )];
        let task = live_task(&jobs, "in_progress", at(1_000)).expect("classified");
        assert_eq!(task.progress, TaskProgress::Publishing);
    }

    /// A running publish row is publishing — the build read `success`
    /// before the publish was written.
    #[test]
    fn a_running_publish_row_is_publishing() {
        let jobs = vec![
            live_job(
                build_name(),
                "completed",
                Some("success"),
                Some(100),
                vec![],
            ),
            live_job(publish_name(), "in_progress", None, None, vec![]),
        ];
        let task = live_task(&jobs, "in_progress", at(1_000)).expect("classified");
        assert_eq!(task.progress, TaskProgress::Publishing);
    }

    /// A `failure` row whose verdict step is still writing inside the
    /// settle window is `Settling`, not a premature class.
    #[test]
    fn a_failure_still_settling_is_settling() {
        let jobs = vec![live_job(
            build_name(),
            "completed",
            Some("failure"),
            Some(995),
            vec![live_step(
                "Run the untrusted build stage",
                "in_progress",
                None,
            )],
        )];
        let task = live_task(&jobs, "failure", at(1_000)).expect("classified");
        assert_eq!(task.progress, TaskProgress::Settling);
    }

    /// A failure past the settle window is `Failed` — the first
    /// unsettled step names where the runner was lost.
    #[test]
    fn a_failure_past_the_settle_window_is_failed() {
        let jobs = vec![live_job(
            build_name(),
            "completed",
            Some("failure"),
            Some(100),
            vec![live_step(
                "Run the untrusted build stage",
                "in_progress",
                None,
            )],
        )];
        let task = live_task(&jobs, "failure", at(1_000)).expect("classified");
        assert!(matches!(
            task.progress,
            TaskProgress::Failed(TaskFailure::Run(RunFailure::Infrastructure { .. }))
        ));
    }

    /// A success run reads `Done`, whatever its rows still write.
    #[test]
    fn a_succeeded_run_is_done() {
        let jobs = vec![
            live_job(
                build_name(),
                "completed",
                Some("success"),
                Some(100),
                vec![],
            ),
            live_job(publish_name(), "in_progress", None, None, vec![]),
        ];
        let task = live_task(&jobs, "success", at(1_000)).expect("classified");
        assert_eq!(task.progress, TaskProgress::Done);
    }

    /// A run landed but its build job has not — the empty page reads
    /// `Queued`, not an error.
    #[test]
    fn an_empty_page_is_queued() {
        let task = live_task(&[], "in_progress", at(1_000)).expect("classified");
        assert_eq!(task.progress, TaskProgress::Queued);
    }

    /// A build row reporting a status the live table does not name is
    /// a schema surprise, not a bucket.
    #[test]
    fn an_unknown_build_status_fails() {
        let jobs = vec![live_job(build_name(), "hiccup", None, Some(900), vec![])];
        assert!(live_task(&jobs, "in_progress", at(1_000)).is_err());
    }

    // ----- The shared failure class (stow#853) -----

    /// A failed run's class comes from the named job's log — the row
    /// the fetch asks for.
    #[test]
    fn failure_log_job_names_the_failed_row() {
        let failure = TaskFailure::Run(RunFailure::Verdict {
            job: build_name().to_owned(),
            step: "Run the untrusted build stage".to_owned(),
            html_url: String::new(),
        });
        let mut row = job_row(build_name(), Some("failure"), vec![]);
        row.id = 42;
        assert_eq!(
            failure_log_job(&failure, &[row]).map(|row| row.id),
            Some(42)
        );
    }

    /// A named job absent from the page has no log to read — `None`,
    /// the `Unknown` with no evidence.
    #[test]
    fn failure_class_is_unknown_without_a_log() {
        let failure = TaskFailure::Run(RunFailure::Infrastructure {
            job: "-".to_owned(),
            step: None,
            html_url: String::new(),
        });
        assert!(failure_log_job(&failure, &[]).is_none());
        let (_, class, evidence) = failure_class_of(&failure, None);
        assert_eq!(class, FailureClass::Unknown);
        assert_eq!(evidence, None);
    }

    /// The named job's log classifies through `classify_log` — the
    /// same answer `runs failures` reports.
    #[test]
    fn failure_class_reads_the_log() {
        let failure = TaskFailure::Run(RunFailure::Infrastructure {
            job: build_name().to_owned(),
            step: None,
            html_url: String::new(),
        });
        let (job, class, evidence) = failure_class_of(&failure, Some(WINDOWS_LINKER_LOG));
        assert_eq!(job, build_name());
        assert_eq!(class, FailureClass::LinkerUnusable);
        assert_eq!(
            evidence.as_deref(),
            Some("error: linking with `link.exe` failed: exit code: 0xc0000142")
        );
    }

    /// The first page is the attempt-scoped view — the default
    /// `filter=latest` jobs path 502s on rerun runs (stow#852).
    #[test]
    fn run_jobs_url_pins_the_attempt() {
        assert_eq!(
            super::run_jobs_url(crate::github::API_BASE, 42, 3),
            format!(
                "{}/repos/{}/actions/runs/42/attempts/3/jobs?per_page=100",
                crate::github::API_BASE,
                crate::github::REPO
            )
        );
    }

    /// One job row in the page shape the endpoint serves.
    fn job_json(id: u64) -> String {
        format!(
            "{{\"id\":{id},\"name\":\"job {id}\",\"status\":\"completed\",\"conclusion\":\"success\",\"started_at\":null,\"completed_at\":null,\"run_attempt\":1,\"html_url\":\"\",\"steps\":[]}}"
        )
    }

    /// A `RunJobsPage` body of the given job ids — `'static` the way
    /// [`Step`] wants its bodies.
    fn jobs_page(ids: &[u64]) -> &'static str {
        Box::leak(
            format!(
                "{{\"jobs\":[{}]}}",
                ids.iter()
                    .map(|id| job_json(*id))
                    .collect::<Vec<_>>()
                    .join(",")
            )
            .into_boxed_str(),
        )
    }

    /// A loopback server bound ahead of `Loopback::start_on` so its
    /// own address can ride the scripted `Link` headers.
    async fn paged_server(etags: bool) -> (crate::test_server::Loopback, String) {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback binds");
        let base = format!("http://{}", listener.local_addr().expect("bound"));
        let headers = |etag: Option<&str>, link: Option<String>| {
            etag.map_or_else(Vec::new, |etag| {
                vec![("etag".to_owned(), format!("\"{etag}\""))]
            })
            .into_iter()
            .chain(link.map(|link| ("link".to_owned(), link)))
            .collect::<Vec<_>>()
        };
        let server = crate::test_server::Loopback::start_on(
            listener,
            base.clone(),
            vec![
                crate::test_server::Step::RespondWith {
                    status: 200,
                    retry_after: None,
                    headers: headers(
                        etags.then_some("p1"),
                        Some(format!("<{base}/page2>; rel=\"next\"")),
                    ),
                    body: jobs_page(&[1]),
                },
                crate::test_server::Step::RespondWith {
                    status: 200,
                    retry_after: None,
                    headers: headers(etags.then_some("p2"), None),
                    body: jobs_page(&[2]),
                },
                crate::test_server::Step::Respond {
                    status: 304,
                    retry_after: None,
                    body: "",
                },
                crate::test_server::Step::Respond {
                    status: 304,
                    retry_after: None,
                    body: "",
                },
            ],
        );
        (server, base)
    }

    /// The jobs pager follows `Link: <…>; rel="next"`: a run's jobs
    /// can outrun one `per_page=100` page, and both pages' rows must
    /// land in the answer.
    #[tokio::test]
    async fn fetch_attempt_jobs_follows_link_next() {
        let (server, base) = paged_server(false).await;
        let jobs = super::fetch_attempt_jobs(None, &base, 7, 2, None, Backoff::new)
            .await
            .expect("two pages of jobs");
        let heads = server.join().await;
        assert_eq!(
            jobs.iter().map(|job| job.id).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(heads.len(), 2);
        assert_eq!(heads[1].head.uri.path(), "/page2");
    }

    /// A carried [`github::ConditionalPages`] revalidates each page on
    /// the `ETag` its own last 200 served: a second walk sends
    /// `If-None-Match`, and 304s answer the cached pages — including
    /// the first page's cached `next`, so the walk still reaches page
    /// two.
    #[tokio::test]
    async fn fetch_attempt_jobs_revalidates_pages_on_their_own_etags() {
        let (server, base) = paged_server(true).await;
        let mut pages = crate::github::ConditionalPages::new();
        for _ in 0..2 {
            let jobs = super::fetch_attempt_jobs(None, &base, 7, 2, Some(&mut pages), Backoff::new)
                .await
                .expect("the cached walk answers the same rows");
            assert_eq!(
                jobs.iter().map(|job| job.id).collect::<Vec<_>>(),
                vec![1, 2]
            );
        }
        let heads = server.join().await;
        assert_eq!(heads.len(), 4, "two-page walk, twice");
        assert!(heads[0].head.headers.get("if-none-match").is_none());
        assert!(heads[1].head.headers.get("if-none-match").is_none());
        assert_eq!(
            heads[2].head.headers.get("if-none-match").expect("etag"),
            "\"p1\""
        );
        assert_eq!(
            heads[3].head.headers.get("if-none-match").expect("etag"),
            "\"p2\""
        );
        assert_eq!(heads[3].head.uri.path(), "/page2");
    }

    /// A `Link` naming a host off the read's own base is refused — the
    /// operator token must never follow it.
    #[tokio::test]
    async fn fetch_attempt_jobs_refuses_an_off_origin_link() {
        use crate::test_server::{Loopback, Step};

        let server = Loopback::start(vec![Step::RespondWith {
            status: 200,
            retry_after: None,
            headers: vec![(
                "link".to_owned(),
                "<https://example.com/jobs?page=2>; rel=\"next\"".to_owned(),
            )],
            body: jobs_page(&[1]),
        }])
        .await;
        let error = super::fetch_attempt_jobs(None, &server.url, 7, 2, None, Backoff::new)
            .await
            .expect_err("an off-origin link is refused");
        assert!(error.to_string().contains("leaves"), "{error}");
        server.join().await;
    }
}
