//! `stow-admin builds digest` — the daily failed-build digest (stow#778).
//!
//! Once a day `build-failure-digest.yml` runs this: it enumerates the
//! `build-batch.yml` runs that completed `failure` inside the window
//! (the 24 hours to `--until`, default now), reads each run's jobs
//! page and classifies every leg with the shared per-leg classifier
//! (`runs::classify_page` over `stow_types::runs::classify_legs` — a
//! `VERDICT_STEPS` step is the crate's verdict, anything else is
//! infrastructure), pulls the failed job's first error line out of
//! its log, and renders one comment grouping the failures class →
//! crate@version → targets. A failure is a failed *leg*, keyed by the
//! label in its `build` job's name (crate, version, target) and its
//! task hash — one failed leg fails its whole run, so per-run
//! accounting would read near 100% (stow#833).
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
use stow_types::runs::{LegFailure, LegOutcome, RunFailure, RunJobRow};
use stow_types::stow_error;
use stow_types::transient::Backoff;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::github::{self, BUILD_WORKFLOW};
use crate::render::{self, Output};
use crate::runs;
use crate::watchdog;

/// The digest's issue — the single open record a failing day comments
/// on and a clean day closes.
const DIGEST_ISSUE_TITLE: &str = "Daily failed builds";
/// The digest's default look-back: the 24 hours before `--until`.
const DEFAULT_WINDOW: time::Duration = time::Duration::hours(24);
/// How long before it completes a `build-batch.yml` run can have been
/// created: GitHub keeps a queued job up to 24 hours, and the batch's
/// legs then run inside it. The window selects
/// runs by completion, so its listing reaches this far further back.
const RUN_LIFETIME: time::Duration = time::Duration::hours(27);
/// Run inspections in flight at once — each is one jobs read plus one
/// log read, so the GitHub fan-out stays at this stated bound (the same
/// 8 `github::runs_in_range` uses for its subdivision reads).
const INSPECT_CONCURRENCY: usize = 8;
/// A jobs page can be read mid-settle — `classify_legs` answers
/// `Unsettled` for the leg still writing. A completed run's rows land
/// within seconds, so this many repolls this far apart cover it; a
/// page still unsettled then is a GitHub defect worth failing on.
const SETTLE_ATTEMPTS: u32 = 3;
const SETTLE_POLL: Duration = Duration::from_secs(20);

#[derive(Args)]
pub struct BuildsArgs {
    #[command(subcommand)]
    pub command: BuildsCommand,
}

#[derive(Subcommand)]
pub enum BuildsCommand {
    /// Digest the window's failed build-batch legs into one comment on
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

/// A run listing row — the fields the digest reads: the id and
/// attempt for the jobs path and the URL for the comment.
#[derive(Debug, serde::Deserialize)]
struct DigestRun {
    id: u64,
    html_url: String,
    /// The run's latest attempt — the jobs page is read scoped to it
    /// (stow#852).
    run_attempt: u64,
    /// When the run last changed — for a completed run, when it completed.
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

impl github::RunRow for DigestRun {
    fn run_id(&self) -> u64 {
        self.id
    }
}

/// Every `build-batch.yml` run that completed `failure` inside
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

/// One classified leg failure — a row of the digest and one JSON
/// entry.
#[derive(Debug, serde::Serialize)]
struct FailureEntry {
    class: FailureKind,
    crate_name: String,
    version: String,
    target: String,
    /// The leg's task hash — `blake3(task_id)`'s first 16 hex, from the
    /// job-name suffix.
    task_hash: String,
    /// The failed job's name — `"leg <i> / build #<i> …"` /
    /// `"leg <i> / publish #<i> …"`, or `"leg <i>"` for an invariant
    /// failure that names no job.
    job: String,
    /// The failed step's name — `None` when the runner was lost before
    /// a step could fail; a `Concluded` leg carries its job's
    /// conclusion (`timed_out`, …) and an `Invariant` leg its message.
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

/// Poll one run's jobs page until every leg settles — a page read
/// mid-settle answers `Unsettled` legs and is repolled at
/// [`SETTLE_POLL`] rather than misread; a page still unsettled after
/// [`SETTLE_ATTEMPTS`] is a GitHub defect and fails.
async fn classify_run(
    token: &str,
    run_id: u64,
    attempt: u64,
) -> stow_types::error::Result<(Vec<RunJobRow>, Vec<runs::PageLeg>)> {
    let mut attempts = SETTLE_ATTEMPTS;
    loop {
        let jobs = runs::fetch_run_jobs(token, run_id, attempt).await?;
        let legs = runs::classify_page(&jobs, "failure", OffsetDateTime::now_utc())?;
        if legs.iter().all(|leg| leg.outcome != LegOutcome::Unsettled) {
            return Ok((jobs, legs));
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

/// The `(class, job, step)` a failed leg reports — a `VERDICT_STEPS`
/// step is the crate's verdict and everything else is infrastructure;
/// a `Concluded` leg's step slot carries the job's conclusion and an
/// `Invariant` leg's carries its message, since neither names a failed
/// step.
fn failure_fields(
    leg: &runs::PageLeg,
    failure: &LegFailure,
) -> (FailureKind, String, Option<String>, String) {
    match failure {
        LegFailure::Run(RunFailure::Verdict {
            job,
            step,
            html_url,
        }) => (
            FailureKind::Verdict,
            job.clone(),
            Some(step.clone()),
            html_url.clone(),
        ),
        LegFailure::Run(RunFailure::Infrastructure {
            job,
            step,
            html_url,
        }) => (
            FailureKind::Infrastructure,
            job.clone(),
            step.clone(),
            html_url.clone(),
        ),
        LegFailure::Concluded {
            job,
            conclusion,
            html_url,
        } => (
            FailureKind::Infrastructure,
            job.clone(),
            Some(conclusion.clone()),
            html_url.clone(),
        ),
        LegFailure::Invariant(message) => (
            FailureKind::Infrastructure,
            format!("leg {}", leg.leg),
            Some(message.clone()),
            String::new(),
        ),
    }
}

/// Reduce one failed batch run to its digest entries: the attempt's
/// jobs page → one entry per failed leg, keyed by the label in its
/// `build` job's name and its task hash.
async fn inspect_run(token: &str, run: &DigestRun) -> stow_types::error::Result<Vec<FailureEntry>> {
    let (jobs, legs) = classify_run(token, run.id, run.run_attempt).await?;
    let mut entries = Vec::new();
    for leg in &legs {
        let LegOutcome::Failed(failure) = &leg.outcome else {
            continue;
        };
        if !runs::leg_attempted(failure) {
            continue;
        }
        // The leg's build job is the label source; a leg without one
        // (a publish-only invariant) groups under `-`.
        let label = match runs::leg_build_job(&jobs, leg.leg) {
            Some(job) => Some(runs::leg_label(&job.name).ok_or_else(|| {
                stow_error!(
                    "run {} leg {}: build job {:?} has no readable label",
                    run.id,
                    leg.leg,
                    job.name
                )
            })?),
            None => None,
        };
        let (kind, job_name, step, job_url) = failure_fields(leg, failure);
        let error_line = match jobs.iter().find(|job| job.name == job_name) {
            Some(job) => first_error_line(token, job.id).await,
            None => None,
        };
        entries.push(FailureEntry {
            class: kind,
            crate_name: label
                .as_ref()
                .map_or_else(|| "-".to_owned(), |label| label.crate_name.clone()),
            version: label
                .as_ref()
                .map_or_else(|| "-".to_owned(), |label| label.version.clone()),
            target: label.map_or_else(|| "-".to_owned(), |label| label.target),
            task_hash: leg
                .hash
                .as_ref()
                .map_or_else(|| "-".to_owned(), ToString::to_string),
            job: job_name,
            step,
            error_line,
            run_url: if job_url.is_empty() {
                run.html_url.clone()
            } else {
                job_url
            },
        });
    }
    Ok(entries)
}

// ===== Rendering =====

/// A `name | legs` count row of the digest's two summary tables.
#[derive(Debug, serde::Serialize)]
struct CountRow {
    name: String,
    legs: usize,
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
    legs: usize,
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
                    failures.sort_by(|a, b| a.target.cmp(&b.target).then(a.job.cmp(&b.job)));
                    CrateGroup {
                        crate_name,
                        version,
                        failures,
                    }
                })
                .collect();
            ClassGroup {
                label: class.label(),
                legs: class_counts[&class],
                crates,
            }
        })
        .collect();
    let class_counts = class_counts
        .into_iter()
        .map(|(class, legs)| CountRow {
            name: class.label().to_owned(),
            legs,
        })
        .collect();
    let target_counts = target_counts
        .into_iter()
        .map(|(name, legs)| CountRow { name, legs })
        .collect();
    (class_counts, target_counts, groups)
}

/// The digest comment — the issue comment's body and the dry-run print.
#[derive(Template)]
#[template(path = "builds/digest.md")]
struct DigestTemplate<'a> {
    since: &'a str,
    until: &'a str,
    failed_legs: usize,
    failed_runs: usize,
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
    failed_legs: usize,
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
    let entries: Vec<FailureEntry> =
        futures_util::stream::iter(failed_runs.iter().map(|run| inspect_run(token, run)))
            .buffered(INSPECT_CONCURRENCY)
            .try_collect::<Vec<_>>()
            .await?
            .into_iter()
            .flatten()
            .collect();
    let (class_counts, target_counts, groups) = group_failures(entries);
    let comment = DigestTemplate {
        since: &since_text,
        until: &until_text,
        failed_legs: groups.iter().map(|group| group.legs).sum(),
        failed_runs: failed_runs.len(),
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
        let failed_legs = groups.iter().map(|group| group.legs).sum();
        match plan_delivery(failed_legs, open_issue.as_ref().map(|issue| issue.number)) {
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
        failed_legs: groups.iter().map(|group| group.legs).sum(),
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
    use stow_types::api::TaskHash;

    /// The `failure_fields` mapping per `LegFailure` shape: a verdict
    /// step is the crate's, a `timed_out` conclusion is
    /// infrastructure, and an invariant names its leg.
    #[test]
    fn failure_fields_map_every_leg_failure_shape() {
        let leg_of = |failure: LegFailure| runs::PageLeg {
            leg: 2,
            hash: Some(TaskHash::of("task-a")),
            outcome: LegOutcome::Failed(failure),
        };
        let fields_of = |leg: &runs::PageLeg| match &leg.outcome {
            LegOutcome::Failed(failure) => failure_fields(leg, failure),
            _ => unreachable!(),
        };
        let (kind, _job, step, _url) = fields_of(&leg_of(LegFailure::Run(RunFailure::Verdict {
            job: "leg 2 / build #2 serde 1.0.0 (x86_64-unknown-linux-gnu) aaaa1111bbbb2222"
                .to_owned(),
            step: "Run the untrusted build stage".to_owned(),
            html_url: String::new(),
        })));
        assert_eq!(kind, FailureKind::Verdict);
        assert_eq!(step.as_deref(), Some("Run the untrusted build stage"));
        let (kind, _job, step, _url) = fields_of(&leg_of(LegFailure::Concluded {
            job: "leg 2 / publish #2 aaaa1111bbbb2222".to_owned(),
            conclusion: "timed_out".to_owned(),
            html_url: String::new(),
        }));
        assert_eq!(kind, FailureKind::Infrastructure);
        assert_eq!(step.as_deref(), Some("timed_out"));
        let (kind, job, _step, _url) = fields_of(&leg_of(LegFailure::Invariant(
            "leg 2 has no jobs".to_owned(),
        )));
        assert_eq!(kind, FailureKind::Infrastructure);
        assert_eq!(job, "leg 2");
    }

    /// A `cancelled`/`skipped` leg is `fail-fast` collateral — never a
    /// digest entry; `timed_out` is a failure worth reporting.
    #[test]
    fn collateral_leg_conclusions_are_not_failures() {
        let attempted = |conclusion: &str| {
            runs::leg_attempted(&LegFailure::Concluded {
                job: "j".to_owned(),
                conclusion: conclusion.to_owned(),
                html_url: String::new(),
            })
        };
        assert!(!attempted("cancelled"));
        assert!(!attempted("skipped"));
        assert!(attempted("timed_out"));
        assert!(runs::leg_attempted(&LegFailure::Run(
            RunFailure::Infrastructure {
                job: "j".to_owned(),
                step: None,
                html_url: String::new(),
            }
        )));
    }

    fn entry(class: FailureKind, crate_name: &str, version: &str, target: &str) -> FailureEntry {
        let hash = TaskHash::of(&format!("{crate_name}-{version}-task"));
        FailureEntry {
            class,
            crate_name: crate_name.to_owned(),
            version: version.to_owned(),
            target: target.to_owned(),
            task_hash: hash.to_string(),
            job: format!("leg 0 / build #0 {crate_name} {version} ({target}) {hash}"),
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
        assert_eq!(class_counts[0].legs, 2);
        assert_eq!(class_counts[1].name, "infrastructure");
        assert_eq!(class_counts[1].legs, 1);
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
            failed_legs: 3,
            failed_runs: 2,
            class_counts: &class_counts,
            target_counts: &target_counts,
            groups: &groups,
        }
        .render()
        .expect("render");
        let verdict = comment.find("verdict").expect("class named");
        let infrastructure = comment.find("infrastructure").expect("class named");
        assert!(verdict < infrastructure, "verdict leads");
        assert!(comment.contains("**3 failed leg(s) across 2 failed `build-batch.yml` run(s)**"));
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
            html_url: String::new(),
            run_attempt: 1,
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
