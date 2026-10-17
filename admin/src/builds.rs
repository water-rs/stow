//! `stow-admin builds digest` — the daily failed-build digest (stow#778).
//!
//! Once a day `build-failure-digest.yml` runs this: it enumerates the
//! `build-crate.yml` runs that completed `failure` inside the window
//! (the 24 hours to `--until`, default now), reads each run's jobs page
//! and classifies the failure exactly as the manual preheat driver does
//! (`runs::classify_failure` — a `VERDICT_STEPS` step is the crate's
//! verdict, anything else is infrastructure), pulls the failed job's
//! first error line out of its log, and renders one comment grouping the
//! failures class → crate@version → targets.
//!
//! Delivery is the `incident`-labelled issue `Daily failed builds` — the
//! one channel this digest keeps (AGENTS.md: unlike the watchdog's
//! alerts it sends no mail). A window with failures posts one comment,
//! opening the issue on the first failing day; a clean window sends
//! nothing and closes the issue when it is open. The command exits
//! non-zero when the issue channel failed — there is no second channel
//! to carry it.
//!
//! Costs: `runs_in_range` reads the whole window past the 1000-row
//! listing cap; per failed run one jobs read (plus a bounded repoll for
//! a page read mid-settle) and one job-log read, at
//! [`INSPECT_CONCURRENCY`] at once; delivery is one label read plus at
//! most two writes.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

use askama::Template;
use clap::{Args, Subcommand};
use futures_util::{StreamExt as _, TryStreamExt as _};
use stow_types::api::{CI_TARGET_TRIPLES, task_id_segment};
use stow_types::records::parse_run_title;
use stow_types::stow_error;
use stow_types::transient::Backoff;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::github::{self, BUILD_WORKFLOW};
use crate::render::{self, Output};
use crate::runs::{self, RunFailure, RunJobsPage, classify_failure};
use crate::watchdog;

/// The digest's issue — the single open record a failing day comments
/// on and a clean day closes.
const DIGEST_ISSUE_TITLE: &str = "Daily failed builds";
/// The digest's default look-back: the 24 hours before `--until`.
const DEFAULT_WINDOW: time::Duration = time::Duration::hours(24);
/// How long before it completes a `build-crate.yml` run can have been
/// created: GitHub keeps a queued job up to 24 hours, and the build and
/// publish jobs then run at most 120 + 60 minutes. The window selects
/// runs by completion, so its listing reaches this far further back.
const RUN_LIFETIME: time::Duration = time::Duration::hours(27);
/// Run inspections in flight at once — each is one jobs read plus one
/// log read, so the GitHub fan-out stays at this stated bound (the same
/// 8 `github::runs_in_range` uses for its subdivision reads).
const INSPECT_CONCURRENCY: usize = 8;
/// A jobs page can be read mid-settle — `classify_failure` answers
/// `None`. A completed run's rows land within seconds, so this many
/// repolls this far apart cover it; a page still unsettled then is a
/// GitHub defect worth failing on.
const SETTLE_ATTEMPTS: u32 = 3;
const SETTLE_POLL: Duration = Duration::from_secs(20);

#[derive(Args)]
pub struct BuildsArgs {
    #[command(subcommand)]
    pub command: BuildsCommand,
}

#[derive(Subcommand)]
pub enum BuildsCommand {
    /// Digest the window's failed build-crate runs into one comment on
    /// the `Daily failed builds` incident issue.
    Digest(DigestArgs),
}

#[derive(Args)]
pub struct DigestArgs {
    /// Window start, RFC 3339 — defaults to 24 h before `--until`.
    #[arg(long, value_parser = parse_time)]
    pub since: Option<OffsetDateTime>,
    /// Window end, RFC 3339 — defaults to now.
    #[arg(long, value_parser = parse_time)]
    pub until: Option<OffsetDateTime>,
    /// Print the digest and touch nothing — no issue read or write.
    #[arg(long)]
    pub dry_run: bool,
}

/// `--since`/`--until`'s RFC 3339 parse.
fn parse_time(raw: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(raw, &Rfc3339).map_err(|error| format!("{raw}: {error}"))
}

pub async fn run(token: &str, args: BuildsArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        BuildsCommand::Digest(args) => digest(token, args, output).await,
    }
}

// ===== Collecting the failures =====

/// A run listing row — the fields the digest reads: the id for the jobs
/// path, the title for `<rustc>-<task_id>`, the URL for the comment.
#[derive(Debug, serde::Deserialize)]
struct DigestRun {
    id: u64,
    display_title: String,
    html_url: String,
    /// When the run last changed — for a completed run, when it completed.
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

impl github::RunRow for DigestRun {
    fn run_id(&self) -> u64 {
        self.id
    }
}

/// Every `build-crate.yml` run that completed `failure` inside
/// `(since, until]`. GitHub filters runs by creation time, and a run can
/// complete up to [`RUN_LIFETIME`] after it was created, so the listing
/// starts that much earlier and the completion time selects — a run
/// created before one digest and failing after it lands in the next.
/// Range enumeration reads past the 1000-row cap, so a dense failure
/// wave cannot drop its tail (stow#555).
async fn fetch_failed_runs(
    token: &str,
    since: OffsetDateTime,
    until: OffsetDateTime,
) -> stow_types::error::Result<Vec<DigestRun>> {
    let listed = github::runs_in_range(
        BUILD_WORKFLOW,
        "status=failure",
        since - RUN_LIFETIME,
        until,
        |path| async move {
            github::get::<github::RunsPage<DigestRun>>(token, &path, Backoff::new()).await
        },
    )
    .await?;
    Ok(completed_in(listed, since, until))
}

/// The runs that completed inside `(since, until]`.
fn completed_in(
    runs: Vec<DigestRun>,
    since: OffsetDateTime,
    until: OffsetDateTime,
) -> Vec<DigestRun> {
    runs.into_iter()
        .filter(|run| run.updated_at > since && run.updated_at <= until)
        .collect()
}

/// What a `<rustc>-<task_id>` task id carries — the grouping keys the
/// digest needs. Written by `TaskNodeIdentity::task_id` as
/// `<crate>-<version>-<features hash>-<target>-<rustc>-d<dep hash>`,
/// `-host` for host-side nodes, every `-` inside a segment spelled `_`.
#[derive(Debug)]
struct TaskId {
    crate_name: String,
    version: String,
    target: String,
    host_side: bool,
}

/// Parse a canonical task id back into its grouping fields. The four
/// tail segments are fixed-shape (`-d<64 hex>`, rustc, target, `<64
/// hex>`) so they split unambiguously; the remaining head is
/// `<crate>-<version>` where a crate name's dashes make the boundary
/// ambiguous only to a left-to-right reader — the rightmost `-` ahead
/// of a semver tail leads the version, because a prerelease's dashes
/// fall inside it and no crate segment parses as semver. The target
/// segment is [`task_id_segment`]-spelled; a triple can itself carry
/// `_` (`x86_64`), so it decodes by matching the fleet's
/// [`CI_TARGET_TRIPLES`] rather than reversing the spelling. `None` is
/// not a canonical task id: the run is not one ours could have made.
fn parse_task_id(task_id: &str) -> Option<TaskId> {
    let (body, host_side) = task_id
        .strip_suffix("-host")
        .map_or((task_id, false), |body| (body, true));
    let is_digest = |s: &str| s.len() == 64 && s.bytes().all(|byte| byte.is_ascii_hexdigit());
    let (body, dependency) = body.rsplit_once('-')?;
    if !dependency.starts_with('d') || !is_digest(&dependency[1..]) {
        return None;
    }
    let (body, _rustc) = body.rsplit_once('-')?;
    let (body, target) = body.rsplit_once('-')?;
    let (head, features) = body.rsplit_once('-')?;
    if !is_digest(features) {
        return None;
    }
    let target = CI_TARGET_TRIPLES
        .iter()
        .find(|triple| task_id_segment(triple) == target)?;
    for (index, _) in head.match_indices('-').rev() {
        let version = &head[index + 1..];
        if semver::Version::parse(version).is_ok() {
            let crate_name = &head[..index];
            return (!crate_name.is_empty()).then(|| TaskId {
                crate_name: crate_name.to_owned(),
                version: version.to_owned(),
                target: (*target).to_owned(),
                host_side,
            });
        }
    }
    None
}

/// One classified failure — a row of the digest and one JSON entry.
#[derive(Debug, serde::Serialize)]
struct FailureEntry {
    class: FailureKind,
    crate_name: String,
    version: String,
    target: String,
    host_side: bool,
    /// The failed job's name — `"-"` when no job failed
    /// (`startup_failure`).
    job: String,
    /// The failed step's name — `None` when the runner was lost before
    /// a step could fail.
    #[serde(skip_serializing_if = "Option::is_none")]
    step: Option<String>,
    /// The failed job log's first error line — `None` when the log was
    /// unreadable or carried none.
    #[serde(skip_serializing_if = "Option::is_none")]
    error_line: Option<String>,
    run_url: String,
}

/// The digest's grouping class — the `RunFailure` variants' report
/// names. `Verdict` sorts first: it is the class an operator reads for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum FailureKind {
    /// The crate's own outcome — a `VERDICT_STEPS` step failed.
    Verdict,
    /// Runner setup, toolchain install, artifact transfer, a lost or
    /// never-assigned runner.
    Infrastructure,
}

impl FailureKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Verdict => "verdict",
            Self::Infrastructure => "infrastructure",
        }
    }
}

/// Poll one run's jobs page until `classify_failure` answers — a page
/// read mid-settle answers `None` and is repolled at [`SETTLE_POLL`]
/// rather than misread; a page still unsettled after
/// [`SETTLE_ATTEMPTS`] is a GitHub defect and fails.
async fn classify_run(
    token: &str,
    run_id: u64,
) -> stow_types::error::Result<(RunJobsPage, RunFailure)> {
    let path = format!("actions/runs/{run_id}/jobs?per_page=100");
    let mut attempts = SETTLE_ATTEMPTS;
    loop {
        let page: RunJobsPage = github::get(token, &path, Backoff::new()).await?;
        if let Some(class) = classify_failure(&page.jobs, OffsetDateTime::now_utc())? {
            return Ok((page, class));
        }
        attempts -= 1;
        if attempts == 0 {
            return Err(stow_error!(
                "run {run_id}: jobs page still settling after {SETTLE_ATTEMPTS} reads"
            ));
        }
        tokio::time::sleep(SETTLE_POLL).await;
    }
}

/// The failed job's log's first error line — `None` when the log is
/// unreadable (expired retention, a runner that never wrote one) or
/// carries no error line.
async fn first_error_line(token: &str, job_id: u64) -> Option<String> {
    let url = format!(
        "{}/repos/{}/actions/jobs/{job_id}/logs",
        github::API_BASE,
        github::REPO
    );
    match github::get_text(token, &url, Backoff::new()).await {
        Ok(log) => runs::first_error_line(&log),
        Err(error) => {
            tracing::warn!(job_id, %error, "job log unavailable");
            None
        }
    }
}

/// Reduce one failed run to its digest entry: title → crate, version,
/// target; jobs page → class, job and step; the failed job's log → the
/// first error line.
async fn inspect_run(token: &str, run: &DigestRun) -> stow_types::error::Result<FailureEntry> {
    let (_rustc, task_id) = parse_run_title(&run.display_title).ok_or_else(|| {
        stow_error!(
            "run {} title {:?} is not `<rustc>-<task_id>`",
            run.id,
            run.display_title
        )
    })?;
    let task = parse_task_id(task_id).ok_or_else(|| {
        stow_error!(
            "run {} task id {task_id:?} is not a canonical task id",
            run.id
        )
    })?;
    let (page, class) = classify_run(token, run.id).await?;
    let (kind, job_name, step) = match class {
        RunFailure::Verdict { job, step } => (FailureKind::Verdict, job, Some(step)),
        RunFailure::Infrastructure { job, step } => (FailureKind::Infrastructure, job, step),
    };
    let error_line = match page.jobs.iter().find(|job| job.name == job_name) {
        Some(job) => first_error_line(token, job.id).await,
        None => None,
    };
    Ok(FailureEntry {
        class: kind,
        crate_name: task.crate_name,
        version: task.version,
        target: task.target,
        host_side: task.host_side,
        job: job_name,
        step,
        error_line,
        run_url: run.html_url.clone(),
    })
}

// ===== Rendering =====

/// A `name | runs` count row of the digest's two summary tables.
#[derive(Debug, serde::Serialize)]
struct CountRow {
    name: String,
    runs: usize,
}

/// One crate's failures inside a class.
#[derive(Debug, serde::Serialize)]
struct CrateGroup {
    crate_name: String,
    version: String,
    failures: Vec<FailureEntry>,
}

/// One class section of the digest.
#[derive(Debug, serde::Serialize)]
struct ClassGroup {
    label: &'static str,
    runs: usize,
    crates: Vec<CrateGroup>,
}

/// Count and group the window's failures: per class, per target, then
/// class → crate@version → per-target rows.
fn group_failures(entries: Vec<FailureEntry>) -> (Vec<CountRow>, Vec<CountRow>, Vec<ClassGroup>) {
    let mut class_counts: BTreeMap<FailureKind, usize> = BTreeMap::new();
    let mut target_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_class: BTreeMap<FailureKind, BTreeMap<(String, String), Vec<FailureEntry>>> =
        BTreeMap::new();
    for entry in entries {
        *class_counts.entry(entry.class).or_default() += 1;
        *target_counts.entry(entry.target.clone()).or_default() += 1;
        by_class
            .entry(entry.class)
            .or_default()
            .entry((entry.crate_name.clone(), entry.version.clone()))
            .or_default()
            .push(entry);
    }
    let groups = by_class
        .into_iter()
        .map(|(class, crates)| {
            let crates = crates
                .into_iter()
                .map(|((crate_name, version), mut failures)| {
                    failures.sort_by(|a, b| {
                        a.target
                            .cmp(&b.target)
                            .then(a.host_side.cmp(&b.host_side))
                            .then(a.job.cmp(&b.job))
                    });
                    CrateGroup {
                        crate_name,
                        version,
                        failures,
                    }
                })
                .collect();
            ClassGroup {
                label: class.label(),
                runs: class_counts[&class],
                crates,
            }
        })
        .collect();
    let class_counts = class_counts
        .into_iter()
        .map(|(class, runs)| CountRow {
            name: class.label().to_owned(),
            runs,
        })
        .collect();
    let target_counts = target_counts
        .into_iter()
        .map(|(name, runs)| CountRow { name, runs })
        .collect();
    (class_counts, target_counts, groups)
}

/// The digest comment — the issue comment's body and the dry-run print.
#[derive(Template)]
#[template(path = "builds/digest.md")]
struct DigestTemplate<'a> {
    since: &'a str,
    until: &'a str,
    total: usize,
    class_counts: &'a [CountRow],
    target_counts: &'a [CountRow],
    groups: &'a [ClassGroup],
}

/// The body `Daily failed builds` is opened with — fixed text, so it
/// is a file the way every other rendered document here is.
const ISSUE_BODY: &str = include_str!("../templates/builds/issue.md");

/// The close comment a clean window leaves.
#[derive(Template)]
#[template(path = "builds/closed.md")]
struct ClosedTemplate<'a> {
    since: &'a str,
    until: &'a str,
}

// ===== Delivery =====

/// What the issue channel owes the rendered digest — the pure
/// decision, so the zero-failure contract is testable without a
/// network.
#[derive(Debug, PartialEq, Eq)]
enum Delivery {
    /// Find-or-create the digest issue and post the comment.
    Comment,
    /// Close the open issue — a clean window ends the record.
    Close(u64),
    /// Clean window, no open issue — send nothing.
    Nothing,
}

const fn plan_delivery(failures: usize, open_issue: Option<u64>) -> Delivery {
    match (failures > 0, open_issue) {
        (true, _) => Delivery::Comment,
        (false, Some(issue)) => Delivery::Close(issue),
        (false, None) => Delivery::Nothing,
    }
}

/// The open `Daily failed builds` issue — `incident`-labelled,
/// title-matched, PRs excluded (the issues endpoint serves them too).
async fn find_digest_issue(gh_token: &str) -> Result<Option<watchdog::GhIssue>, String> {
    let issues: Vec<watchdog::GhIssue> = github::get(
        gh_token,
        &format!(
            "issues?labels={}&state=open&per_page=100",
            watchdog::INCIDENT_LABEL
        ),
        Backoff::new(),
    )
    .await
    .map_err(|error| error.to_string())?;
    Ok(issues
        .into_iter()
        .find(|issue| issue.pull_request.is_none() && issue.title == DIGEST_ISSUE_TITLE))
}

/// Find-or-create the digest issue and post `body` as its comment.
async fn post_digest(
    gh_token: &str,
    body: &str,
    open_issue: Option<watchdog::GhIssue>,
    actions: &mut Vec<String>,
) -> Result<(), String> {
    watchdog::ensure_label(github::API_BASE, gh_token, Duration::from_secs(30))
        .await
        .map_err(|error| format!("label: {error}"))?;
    let number = if let Some(issue) = open_issue {
        issue.number
    } else {
        let issue: watchdog::GhIssue = github::post(
            gh_token,
            "issues",
            &watchdog::IssueNew {
                title: DIGEST_ISSUE_TITLE,
                body: ISSUE_BODY,
                labels: [watchdog::INCIDENT_LABEL],
            },
        )
        .await
        .map_err(|error| format!("create issue: {error}"))?;
        actions.push(format!("issue opened: {}", issue.html_url));
        issue.number
    };
    watchdog::post_comment(gh_token, number, body).await?;
    actions.push(format!("digest comment posted on #{number}"));
    Ok(())
}

// ===== The command =====

/// The serialized run report — `--json` and the table view share it.
#[derive(Debug, serde::Serialize)]
struct DigestReport {
    dry_run: bool,
    since: String,
    until: String,
    failed_runs: usize,
    class_counts: Vec<CountRow>,
    target_counts: Vec<CountRow>,
    groups: Vec<ClassGroup>,
    /// The delivery channel's outcome — one line per applied step.
    actions: Vec<String>,
    /// Delivery failures — any entry fails the run.
    failures: Vec<String>,
}

async fn digest(token: &str, args: DigestArgs, output: Output) -> stow_types::error::Result<()> {
    let until = args.until.unwrap_or_else(OffsetDateTime::now_utc);
    let since = args.since.unwrap_or_else(|| until - DEFAULT_WINDOW);
    if since > until {
        return Err(stow_error!("--since {since} is after --until {until}"));
    }
    let rfc3339 = |at: OffsetDateTime| {
        at.format(&Rfc3339)
            .map_err(|error| stow_error!("format {at} as RFC 3339: {error}"))
    };
    let (since_text, until_text) = (rfc3339(since)?, rfc3339(until)?);

    let failed_runs = fetch_failed_runs(token, since, until).await?;
    // Independent runs inspect concurrently under the stated bound —
    // serial jobs+log reads would make a dense wave's digest take
    // minutes it does not need to.
    let entries = futures_util::stream::iter(failed_runs.iter().map(|run| inspect_run(token, run)))
        .buffered(INSPECT_CONCURRENCY)
        .try_collect::<Vec<_>>()
        .await?;
    let (class_counts, target_counts, groups) = group_failures(entries);
    let comment = DigestTemplate {
        since: &since_text,
        until: &until_text,
        total: failed_runs.len(),
        class_counts: &class_counts,
        target_counts: &target_counts,
        groups: &groups,
    }
    .render()
    .map_err(|error| stow_error!("render digest: {error}"))?;

    let mut actions = Vec::new();
    let mut failures = Vec::new();
    if args.dry_run {
        actions.push("dry run — nothing sent".to_owned());
    } else {
        let open_issue = match find_digest_issue(token).await {
            Ok(issue) => issue,
            Err(error) => {
                failures.push(format!("find digest issue: {error}"));
                None
            }
        };
        match plan_delivery(
            failed_runs.len(),
            open_issue.as_ref().map(|issue| issue.number),
        ) {
            Delivery::Comment => {
                if let Err(error) = post_digest(token, &comment, open_issue, &mut actions).await {
                    failures.push(error);
                }
            }
            Delivery::Close(number) => {
                let closed = ClosedTemplate {
                    since: &since_text,
                    until: &until_text,
                }
                .render()
                .map_err(|error| stow_error!("render close comment: {error}"))?;
                match watchdog::close_incident(token, number, &closed).await {
                    Ok(()) => actions.push(format!("digest issue #{number} closed")),
                    Err(error) => failures.push(error),
                }
            }
            Delivery::Nothing => {
                actions.push("no failures and no open digest issue — nothing sent".to_owned());
            }
        }
    }

    let report = DigestReport {
        dry_run: args.dry_run,
        since: since_text,
        until: until_text,
        failed_runs: failed_runs.len(),
        class_counts,
        target_counts,
        groups,
        actions,
        failures,
    };
    render::emit(output, &report, |report| {
        let mut out = String::new();
        if report.dry_run {
            let _ = writeln!(out, "dry run — nothing sent\n");
        }
        let _ = write!(out, "{comment}");
        for action in &report.actions {
            let _ = write!(out, "\n{action}");
        }
        for failure in &report.failures {
            let _ = write!(out, "\nFAILED {failure}");
        }
        out
    })?;
    if report.failures.is_empty() {
        Ok(())
    } else {
        Err(stow_error!("digest delivery failed — see report"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real titles a wave stamps: `1.99.0-<task_id>`.
    #[test]
    fn task_id_parses_crate_version_target() {
        let title = "1.99.0-gix-hash-0.27.0-ddd99a14d9fad9015908827b4edb6623350306075bbd2c2e5e600164d88b9618-aarch64_pc_windows_msvc-1.99.0-d378731025cfb98afa085f4362b1073bfd51298580ac931cc730d70f247998838";
        let (_rustc, task_id) = parse_run_title(title).expect("title");
        let task = parse_task_id(task_id).expect("task id");
        assert_eq!(task.crate_name, "gix-hash");
        assert_eq!(task.version, "0.27.0");
        assert_eq!(task.target, "aarch64-pc-windows-msvc");
        assert!(!task.host_side);
    }

    /// A host-side node carries the `-host` suffix after the dependency
    /// digest (run 38977101174's title).
    #[test]
    fn task_id_parses_the_host_suffix() {
        let title = "1.99.0-pest-2.9.4-b6a51989e7bc432a09ddf68698dd30718ef7d6986033e980ac4b118103106865-x86_64_unknown_linux_gnu-1.99.0-de864c6f3bff846e16a4dc2b8967662e27da4387268008fa6eb8d7216d25938d7-host";
        let (_rustc, task_id) = parse_run_title(title).expect("title");
        let task = parse_task_id(task_id).expect("task id");
        assert_eq!(task.crate_name, "pest");
        assert_eq!(task.version, "2.9.4");
        assert_eq!(task.target, "x86_64-unknown-linux-gnu");
        assert!(task.host_side);
    }

    /// The version boundary is the rightmost `-` ahead of a semver
    /// tail: a prerelease's own dash stays inside the version, and a
    /// crate named like a version keeps its dashes.
    #[test]
    fn task_id_version_boundary_prefers_the_rightmost_semver_tail() {
        let digest = "a".repeat(64);
        let parsed = |name_version: &str| {
            parse_task_id(&format!(
                "{name_version}-{digest}-x86_64_unknown_linux_gnu-1.99.0-d{digest}"
            ))
            .map(|task| (task.crate_name, task.version))
        };
        assert_eq!(
            parsed("serde-1.0.0-rc.1"),
            Some(("serde".to_owned(), "1.0.0-rc.1".to_owned()))
        );
        assert_eq!(
            parsed("aws-lc-sys-0.46.0"),
            Some(("aws-lc-sys".to_owned(), "0.46.0".to_owned()))
        );
        assert_eq!(
            parsed("foo-1.0.0-2.0.0"),
            Some(("foo-1.0.0".to_owned(), "2.0.0".to_owned()))
        );
    }

    /// A title that is not `<rustc>-<task_id>` — a workflow name never
    /// rendered, a hand edit — parses nothing. `parse_run_title` is the
    /// shallow `<x>-<y>` split; the canonical task-id parse is what
    /// rejects the tail.
    #[test]
    fn a_non_task_title_parses_nothing() {
        assert!(parse_run_title("manual dispatch").is_none());
        let (_, task_id) = parse_run_title("build-crate").expect("splits at the dash");
        assert!(parse_task_id(task_id).is_none());
    }

    /// The target segment cannot be decoded by reversing the `-`→`_`
    /// spelling — a triple can carry `_` itself (`x86_64`). Every fleet
    /// triple encodes through `task_id_segment` and decodes by matching.
    #[test]
    fn every_ci_target_decodes() {
        let digest = "a".repeat(64);
        for target in CI_TARGET_TRIPLES {
            let task_id = format!(
                "serde-1.0.0-{digest}-{}-1.99.0-d{digest}",
                task_id_segment(target)
            );
            assert_eq!(parse_task_id(&task_id).expect(target).target, *target);
        }
    }

    fn entry(class: FailureKind, crate_name: &str, version: &str, target: &str) -> FailureEntry {
        FailureEntry {
            class,
            crate_name: crate_name.to_owned(),
            version: version.to_owned(),
            target: target.to_owned(),
            host_side: false,
            job: format!("build {crate_name} {version} ({target})"),
            step: Some("Run the untrusted build stage".to_owned()),
            error_line: Some("error: linking with `ld.mold` failed".to_owned()),
            run_url: format!("https://github.com/water-rs/stow/actions/runs/{crate_name}"),
        }
    }

    /// Grouping is class → crate@version → targets: two classes and
    /// three targets land in two sections, the second crate's two
    /// targets as two rows under one heading.
    #[test]
    fn failures_group_class_then_crate_then_target() {
        let entries = vec![
            entry(
                FailureKind::Verdict,
                "serde",
                "1.0.0",
                "aarch64-apple-darwin",
            ),
            entry(
                FailureKind::Verdict,
                "serde",
                "1.0.0",
                "x86_64-pc-windows-msvc",
            ),
            entry(
                FailureKind::Infrastructure,
                "anyhow",
                "1.0.100",
                "wasm32-unknown-unknown",
            ),
        ];
        let (class_counts, target_counts, groups) = group_failures(entries);
        assert_eq!(class_counts.len(), 2);
        assert_eq!(class_counts[0].name, "verdict");
        assert_eq!(class_counts[0].runs, 2);
        assert_eq!(class_counts[1].name, "infrastructure");
        assert_eq!(class_counts[1].runs, 1);
        assert_eq!(target_counts.len(), 3);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].label, "verdict");
        assert_eq!(groups[0].crates.len(), 1);
        assert_eq!(groups[0].crates[0].failures.len(), 2);
        assert_eq!(groups[1].crates[0].crate_name, "anyhow");
    }

    /// The rendered comment leads with the count tables, then one
    /// section per class with its crates and targets.
    #[test]
    fn the_digest_renders_counts_then_groups() {
        let entries = vec![
            entry(
                FailureKind::Verdict,
                "serde",
                "1.0.0",
                "aarch64-apple-darwin",
            ),
            entry(
                FailureKind::Verdict,
                "serde",
                "1.0.0",
                "x86_64-pc-windows-msvc",
            ),
            entry(
                FailureKind::Infrastructure,
                "anyhow",
                "1.0.100",
                "wasm32-unknown-unknown",
            ),
        ];
        let (class_counts, target_counts, groups) = group_failures(entries);
        let comment = DigestTemplate {
            since: "2026-10-15T13:00:00Z",
            until: "2026-10-16T13:00:00Z",
            total: 3,
            class_counts: &class_counts,
            target_counts: &target_counts,
            groups: &groups,
        }
        .render()
        .expect("render");
        let verdict = comment.find("verdict").expect("class named");
        let infrastructure = comment.find("infrastructure").expect("class named");
        assert!(verdict < infrastructure, "verdict leads");
        assert!(comment.contains("| verdict | 2 |"));
        assert!(comment.contains("| `aarch64-apple-darwin` | 1 |"));
        assert!(comment.contains("**serde 1.0.0**"));
        assert!(comment.contains("Run the untrusted build stage"));
        assert!(comment.contains("error: linking with `ld.mold` failed"));
        assert!(comment.contains("/actions/runs/serde"));
    }

    /// A clean window sends nothing — and closes the record when it is
    /// open; a failing window always posts.
    #[test]
    fn delivery_plan_covers_the_zero_failure_contract() {
        assert_eq!(plan_delivery(0, None), Delivery::Nothing);
        assert_eq!(plan_delivery(0, Some(42)), Delivery::Close(42));
        assert_eq!(plan_delivery(3, None), Delivery::Comment);
        assert_eq!(plan_delivery(3, Some(42)), Delivery::Comment);
    }

    /// A run belongs to the window it completed in, whenever it was
    /// created: one created before the window and failing inside it is
    /// counted, one created inside it and failing after it is not.
    #[test]
    fn runs_are_selected_by_completion() {
        let until = OffsetDateTime::parse("2026-10-17T13:00:00Z", &Rfc3339).expect("until");
        let since = until - DEFAULT_WINDOW;
        let run = |id, updated_at: &str| DigestRun {
            id,
            display_title: String::new(),
            html_url: String::new(),
            updated_at: OffsetDateTime::parse(updated_at, &Rfc3339).expect("updated_at"),
        };
        let kept = completed_in(
            vec![
                run(1, "2026-10-16T12:59:59Z"),
                run(2, "2026-10-16T13:00:01Z"),
                run(3, "2026-10-17T13:00:00Z"),
                run(4, "2026-10-17T13:00:01Z"),
            ],
            since,
            until,
        );
        assert_eq!(
            kept.iter().map(|run| run.id).collect::<Vec<_>>(),
            vec![2, 3]
        );
    }
}
