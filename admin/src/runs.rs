//! `stow-admin runs failures --since <duration>` — fetch failed
//! `build-batch.yml` runs from GitHub Actions, classify every leg of
//! each run's jobs page, pull each failed leg's job log, classify the
//! failure, and group by class.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use clap::{Args, Subcommand};
use stow_types::api::TaskHash;
use stow_types::runs::{
    LegFailure, LegJobKind, LegJobName, LegOutcome, RunFailure, RunJobRow, RunJobsPage,
    classify_legs,
};
use stow_types::stow_error;
use stow_types::transient::Backoff;
use time::OffsetDateTime;
use zenwave::ResponseExt as _;

use crate::github::{self, BUILD_WORKFLOW};
use crate::render::{self, Output, Table};

#[derive(Args)]
pub struct RunsArgs {
    #[command(subcommand)]
    pub command: RunsCommand,
}

#[derive(Subcommand)]
pub enum RunsCommand {
    /// List failed build-batch legs in the window, grouped by the
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
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
    // rustc's own diagnostics carry an error code; a linker failure does
    // not, and reports its own line first. An old crate that no longer
    // compiles on the task's toolchain is a permanent answer, not a
    // transient one, so it is worth separating from `unknown`.
    if line.starts_with("error[E") {
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
/// when none match, a run whose log never shows the `stow-build build`
/// step starting died before the wrapper executed — the runner-loss and
/// setup-failure bucket. `watchdog` reuses it for the incident's
/// failure-class breakdown.
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
    // `##[group]Run ./target/release/stow-build …` is the workflow's
    // banner for both wrapper steps (`build` and `publish`); a bare
    // `stow-build` substring would also match the host compile of the
    // binary itself, which runs before the wrapper ever starts.
    if !log.contains("Run ./target/release/stow-build") {
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

// ===== Leg classification =====
//
// `VERDICT_STEPS`, `STEP_SETTLE_WINDOW`, `RunFailure`,
// `classify_failure`, the jobs-page row types and the per-leg
// classifier (`classify_legs`, `LegJobName`, `LegOutcome`,
// `LegFailure`) live in `stow_types::runs` — the edge's batch resolver
// runs the same contract. `classify_log` and its `FailureClass` stay
// here: they read job logs, which only `runs failures`, `builds
// digest` and `watchdog` pull.

/// One leg of a `build-batch.yml` run's jobs page and its outcome.
#[derive(Debug)]
pub struct PageLeg {
    /// The leg index — the `#N` in `leg N / build #N …`.
    pub leg: u32,
    /// The leg's [`TaskHash`] from its job-name suffix.
    pub hash: TaskHash,
    /// The leg's classified outcome.
    pub outcome: LegOutcome,
}

/// Classify every leg present on a `build-batch.yml` run's jobs page —
/// the shared classifier driven by the page itself (stow#833).
///
/// The admin readers hold no batch manifest, so each leg's expected
/// [`TaskHash`] is read out of its own job names: the hash cross-check
/// still fires when one leg's jobs disagree, a leg index repeating a
/// job kind still fails as a duplicate, and a non-leg job name is a
/// schema surprise the caller fails on. Legs come back in index
/// order. A leg with no job rows never ran — under `fail-fast` a
/// run's tail legs can be cancelled before scheduling — and produces
/// no entry: it is neither a completed leg nor a failed one.
/// `Unsettled` outcomes are the caller's signal to repoll.
///
/// `run_conclusion` is the run's reported conclusion — the
/// `startup_failure`-with-no-jobs case the classifier treats as every
/// leg's lost runner.
pub fn classify_page(
    jobs: &[RunJobRow],
    run_conclusion: &str,
    now: OffsetDateTime,
) -> stow_types::error::Result<Vec<PageLeg>> {
    let mut legs: BTreeMap<u32, TaskHash> = BTreeMap::new();
    for job in jobs {
        let Some(parsed) = LegJobName::parse(&job.name) else {
            return Err(stow_error!(
                "batch run jobs page names a non-leg job {:?}",
                job.name
            ));
        };
        // The first job's hash stands as the leg's expected hash; a
        // second job disagreeing fails the leg's hash check inside
        // `classify_legs`.
        legs.entry(parsed.leg).or_insert(parsed.hash);
    }
    let Some(&last) = legs.keys().next_back() else {
        return Ok(Vec::new());
    };
    // Entries for leg indexes absent from the page are never read —
    // `classify_leg` consults `expected[leg]` only for the hash check,
    // which runs only when the leg has jobs — so any valid hash fills
    // them.
    let placeholder: TaskHash = "0000000000000000".parse().expect("16 zero hex");
    let expected: Vec<TaskHash> = (0..=last)
        .map(|leg| {
            legs.get(&leg)
                .cloned()
                .unwrap_or_else(|| placeholder.clone())
        })
        .collect();
    let outcomes = classify_legs(&expected, run_conclusion, jobs, now)?;
    Ok(outcomes
        .into_iter()
        .enumerate()
        .filter_map(|(index, outcome)| {
            let leg = u32::try_from(index).expect("leg index fits u32");
            legs.get(&leg).map(|hash| PageLeg {
                leg,
                hash: hash.clone(),
                outcome,
            })
        })
        .collect())
}

/// Whether a failed leg was actually attempted — a leg whose jobs
/// were `cancelled` or `skipped` is `fail-fast` collateral or an
/// operator's cancel, never a failed build the reports count.
pub fn leg_attempted(failure: &LegFailure) -> bool {
    !matches!(failure, LegFailure::Concluded { conclusion, .. } if matches!(conclusion.as_str(), "cancelled" | "skipped"))
}

/// What a leg's `build` job name carries — the digest's grouping keys
/// and the watchdog's target evidence. `build-batch.yml` writes it as
/// `build #<leg> <crate> <version> (<target>) <hash>` under the
/// `leg <leg> / ` caller prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegLabel {
    /// Crate name as known to crates.io.
    pub crate_name: String,
    /// Exact crate version.
    pub version: String,
    /// Compilation target triple — carried verbatim in the job name.
    pub target: String,
}

/// Parse a leg `build` job's name back into its label.
///
/// [`LegJobName::parse`] has already vetted the
/// `build #<leg> … <16 hex>` frame; what remains between the leg
/// index and the hash is `<crate> <version> (<target>)`, where the
/// version must be semver — neither a crate name nor a target can
/// carry a space, so the splits are unambiguous. `None` on a name
/// that is not a leg `build` job's or whose label does not match —
/// the callers fail fast on it: the run is ours, so an unreadable
/// label is a schema surprise.
pub fn leg_label(job_name: &str) -> Option<LegLabel> {
    let parsed = LegJobName::parse(job_name)?;
    if parsed.kind != LegJobKind::Build {
        return None;
    }
    let segment = job_name.rsplit_once(" / ").map_or(job_name, |(_, s)| s);
    let label = segment
        .strip_prefix(&format!("build #{} ", parsed.leg))?
        .strip_suffix(&format!(" {}", parsed.hash))?;
    let (name_version, target) = label.rsplit_once(" (")?;
    let target = target.strip_suffix(')')?;
    let (crate_name, version) = name_version.split_once(' ')?;
    if crate_name.is_empty() || semver::Version::parse(version).is_err() || target.is_empty() {
        return None;
    }
    Some(LegLabel {
        crate_name: crate_name.to_owned(),
        version: version.to_owned(),
        target: target.to_owned(),
    })
}

/// The leg's `build` job row on the page — its name is the label
/// source and its id the log path for legs that need it.
pub fn leg_build_job(jobs: &[RunJobRow], leg: u32) -> Option<&RunJobRow> {
    jobs.iter().find(|job| {
        LegJobName::parse(&job.name)
            .is_some_and(|name| name.leg == leg && name.kind == LegJobKind::Build)
    })
}

/// Every job row of a run's latest attempt — the whole list, not one
/// page (stow#833).
///
/// A batch carries 2 × `STOW_BATCH_MAX_TASKS` jobs and that bound is
/// configurable, so a single `per_page=100` read silently truncates a
/// large batch; the pager follows the RFC 8288 `Link` header's
/// `rel="next"` (`stow_types::runs::link_next`, the same parse the
/// edge's `attempt_jobs` runs) until GitHub names no next page.
/// `runs failures`, `builds digest` and the watchdog all read their
/// jobs through here — the one pager, nowhere duplicated.
pub async fn fetch_run_jobs(token: &str, run_id: u64) -> stow_types::error::Result<Vec<RunJobRow>> {
    fetch_jobs_pages(
        Some(token),
        &format!(
            "{}/repos/{}/actions/runs/{run_id}/jobs?per_page=100",
            github::API_BASE,
            github::REPO
        ),
    )
    .await
}

/// The pager loop behind [`fetch_run_jobs`] over absolute URLs —
/// split so a test can point the first page at a loopback server.
/// `Authorization` rides only when `token` is `Some` (the same
/// convention `github::send_get` holds for loopback reads).
async fn fetch_jobs_pages(
    token: Option<&str>,
    first_url: &str,
) -> stow_types::error::Result<Vec<RunJobRow>> {
    let mut jobs = Vec::new();
    let mut url = first_url.to_owned();
    loop {
        let response = github::send_get(
            token,
            &url,
            Some("application/vnd.github+json"),
            None,
            Backoff::new(),
        )
        .await
        .map_err(|error| stow_error!("GET {url}: {error}"))?;
        let next = response
            .headers()
            .get("link")
            .and_then(|value| value.to_str().ok())
            .and_then(|header| stow_types::runs::link_next(Some(header)))
            .map(str::to_owned);
        let mut page: RunJobsPage = response
            .error_for_status()
            .await
            .map_err(|error| stow_error!("GET {url}: {error}"))?
            .into_json()
            .await
            .map_err(|error| stow_error!("read {url}: {error}"))?;
        jobs.append(&mut page.jobs);
        let Some(next) = next else { break };
        url = next;
    }
    Ok(jobs)
}

// ===== GitHub REST shapes =====

#[derive(Debug, serde::Deserialize)]
struct WorkflowRun {
    id: u64,
    html_url: String,
}

impl github::RunRow for WorkflowRun {
    fn run_id(&self) -> u64 {
        self.id
    }
}

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
    legs: usize,
    examples: Vec<FailureExample>,
}

/// The `runs failures` payload.
#[derive(Debug, serde::Serialize)]
struct FailuresReport {
    workflow: &'static str,
    since_seconds: u64,
    failed_runs: usize,
    failed_legs: usize,
    groups: Vec<FailureGroup>,
}

pub async fn run(token: &str, args: RunsArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        RunsCommand::Failures(args) => failures(token, args, output).await,
    }
}

/// Every failed run of the batch workflow in the closed window
/// `[now-since, now]` — range enumeration reads the whole window past
/// GitHub's 1000-row listing cap, so a dense failure wave no longer
/// drops its tail (stow#555). One failed leg fails its whole run, so
/// the listing is of runs *carrying* failures — the legs inside are
/// what classify.
async fn fetch_failed_runs(
    token: &str,
    since: std::time::Duration,
) -> stow_types::error::Result<Vec<WorkflowRun>> {
    let until = time::OffsetDateTime::now_utc();
    github::runs_in_range(
        BUILD_WORKFLOW,
        "status=failure",
        until - since,
        until,
        |path| async move {
            github::get::<github::RunsPage<WorkflowRun>>(token, &path, Backoff::new()).await
        },
    )
    .await
}

/// Classify each failed run's legs on its attempt's jobs page, then
/// fetch each failed leg's failed-job log and group the classified
/// failures.
async fn classify_runs(
    token: &str,
    runs: &[WorkflowRun],
) -> stow_types::error::Result<Vec<FailureGroup>> {
    let mut groups: BTreeMap<FailureClass, Vec<FailureExample>> = BTreeMap::new();
    for run in runs {
        let jobs = fetch_run_jobs(token, run.id).await?;
        for leg in classify_page(&jobs, "failure", OffsetDateTime::now_utc())? {
            let LegOutcome::Failed(failure) = &leg.outcome else {
                continue;
            };
            if !leg_attempted(failure) {
                continue;
            }
            let (job_name, log_job) = match failure {
                LegFailure::Run(
                    RunFailure::Verdict { job, .. } | RunFailure::Infrastructure { job, .. },
                )
                | LegFailure::Concluded { job, .. } => {
                    (job.clone(), jobs.iter().find(|row| row.name == *job))
                }
                LegFailure::Invariant(_) => (format!("leg {}", leg.leg), None),
            };
            let (class, evidence) = match (failure, log_job) {
                // An invariant failure is its own evidence — the
                // message names the mismatch; there is no log to read.
                (LegFailure::Invariant(message), _) => {
                    (FailureClass::Unknown, Some(message.clone()))
                }
                (_, None) => (FailureClass::Unknown, None),
                (_, Some(job)) => {
                    let log_url = format!(
                        "https://api.github.com/repos/{}/actions/jobs/{}/logs",
                        github::REPO,
                        job.id
                    );
                    match github::get_text(token, &log_url, Backoff::new()).await {
                        Ok(log) => classify_log(&log),
                        Err(error) => {
                            tracing::warn!(job_id = job.id, %error, "job log unavailable; skipping");
                            continue;
                        }
                    }
                }
            };
            groups.entry(class).or_default().push(FailureExample {
                run_url: run.html_url.clone(),
                job: job_name,
                evidence,
            });
        }
    }
    Ok(groups
        .into_iter()
        .map(|(class, examples)| FailureGroup {
            class,
            legs: examples.len(),
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
    let failed_legs = groups.iter().map(|group| group.legs).sum();

    let report = FailuresReport {
        workflow: BUILD_WORKFLOW,
        since_seconds: args.since.as_secs(),
        failed_runs: runs.len(),
        failed_legs,
        groups,
    };
    render::emit(output, &report, |report| {
        if report.groups.is_empty() {
            return format!(
                "no failed {} legs in the last {}",
                report.workflow,
                render::age(report.since_seconds)
            );
        }
        let mut out = format!(
            "{} failed leg(s) across {} failed {} run(s) in the last {}\n",
            report.failed_legs,
            report.failed_runs,
            report.workflow,
            render::age(report.since_seconds)
        );
        let mut table = Table::new(&["class", "legs", "example"]);
        for group in &report.groups {
            let example = group
                .examples
                .first()
                .map_or("-", |example| example.run_url.as_str());
            table.push([
                group.class.as_str().to_owned(),
                group.legs.to_string(),
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

    use super::{
        FailureClass, LegFailure, LegOutcome, RunFailure, RunJobRow, TaskHash, classify_log,
        classify_page, leg_attempted, leg_label, log_line_body,
    };

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

    /// A linker failure also ends in `could not compile`; its own line
    /// comes first and carries no error code, so the two never collide.
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
        // A runner-loss log has no error line the known classes match and
        // the `stow-build build` step never appears.
        let log = "Waiting for a runner to pick up this job...\n";
        assert_eq!(classify_log(log).0, FailureClass::WrapperNeverExecuted);
    }

    #[test]
    fn unknown_when_wrapper_ran_but_no_pattern_matched() {
        let log = "##[group]Run ./target/release/stow-build build --output-dir /tmp/out\n##[error]error: something odd\n";
        assert_eq!(classify_log(log).0, FailureClass::Unknown);
    }

    #[test]
    fn first_error_line_wins() {
        let log = "##[error]error: toolchain '1.91.1' does not support target 'x'\nerror: failed to download `y`\n";
        assert_eq!(classify_log(log).0, FailureClass::ToolchainTargetMissing);
    }

    // ----- Batch legs (stow#833) -----

    fn at(unix: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(unix).expect("timestamp")
    }

    /// One job row of a `build-batch.yml` run's page — settled
    /// (`completed`) unless the fixture says otherwise.
    fn job_row(name: String, conclusion: Option<&str>, steps: Vec<RunStepRow>) -> RunJobRow {
        RunJobRow {
            id: 0,
            name,
            status: "completed".to_owned(),
            conclusion: conclusion.map(str::to_owned),
            started_at: Some(at(50)),
            completed_at: Some(at(100)),
            run_attempt: 1,
            html_url: String::new(),
            steps,
        }
    }

    /// Leg `i`'s build job name as `build-batch.yml` writes it —
    /// `leg i / build #i <crate> <version> (<target>) <hash>`.
    fn build_name(leg: u32, task_id: &str) -> (TaskHash, String) {
        let hash = TaskHash::of(task_id);
        let name =
            format!("leg {leg} / build #{leg} serde 1.0.0 (x86_64-unknown-linux-gnu) {hash}");
        (hash, name)
    }

    /// Leg `i`'s publish job name — `leg i / publish #i <hash>`.
    fn publish_name(leg: u32, task_id: &str) -> String {
        format!("leg {leg} / publish #{leg} {}", TaskHash::of(task_id))
    }

    /// The build job name's label round-trips: crate, version and the
    /// verbatim target, with or without the `leg N / ` caller prefix.
    #[test]
    fn leg_label_reads_crate_version_target() {
        let hash = TaskHash::of("some-task-id");
        for name in [
            format!("leg 7 / build #7 gix-hash 0.27.0 (aarch64-pc-windows-msvc) {hash}"),
            format!("build #7 gix-hash 0.27.0 (aarch64-pc-windows-msvc) {hash}"),
        ] {
            let label = leg_label(&name).expect("label");
            assert_eq!(label.crate_name, "gix-hash");
            assert_eq!(label.version, "0.27.0");
            assert_eq!(label.target, "aarch64-pc-windows-msvc");
        }
    }

    /// A publish job's name carries no label; anything off the
    /// `<crate> <version> (<target>)` shape — a missing version, a
    /// non-semver one, a missing target — parses nothing.
    #[test]
    fn leg_label_rejects_non_build_and_malformed_names() {
        let hash = TaskHash::of("some-task-id");
        for name in [
            format!("leg 3 / publish #3 {hash}"),
            format!("build #3 serde (x86_64-unknown-linux-gnu) {hash}"),
            format!("build #3 serde not-semver (x86_64-unknown-linux-gnu) {hash}"),
            format!("build #3 serde 1.0.0 x86_64-unknown-linux-gnu {hash}"),
            "build-crate".to_owned(),
        ] {
            assert_eq!(leg_label(&name), None, "{name}");
        }
    }

    /// A failed run's page classifies per leg: the verdict leg is a
    /// failed leg; the cancelled collateral leg is not attempted; the
    /// successful leg is neither.
    #[test]
    fn classify_page_reports_each_leg_on_its_own_merits() {
        let (hash0, build0) = build_name(0, "task-a");
        let (_hash1, build1) = build_name(1, "task-b");
        let (_hash2, build2) = build_name(2, "task-c");
        let jobs = vec![
            job_row(build0, Some("success"), vec![]),
            job_row(publish_name(0, "task-a"), Some("success"), vec![]),
            job_row(
                build1,
                Some("failure"),
                vec![RunStepRow {
                    name: "Run the untrusted build stage".to_owned(),
                    status: "completed".to_owned(),
                    conclusion: Some("failure".to_owned()),
                }],
            ),
            job_row(publish_name(1, "task-b"), Some("skipped"), vec![]),
            job_row(build2, Some("cancelled"), vec![]),
            job_row(publish_name(2, "task-c"), Some("cancelled"), vec![]),
        ];
        let legs = classify_page(&jobs, "failure", at(1_000)).expect("classified");
        assert_eq!(legs.len(), 3);
        assert_eq!(legs[0].hash, hash0);
        assert!(matches!(legs[0].outcome, LegOutcome::Succeeded { .. }));
        let LegOutcome::Failed(LegFailure::Run(RunFailure::Verdict { .. })) = &legs[1].outcome
        else {
            panic!("leg 1 is the crate's verdict: {:?}", legs[1].outcome);
        };
        let LegOutcome::Failed(failure) = &legs[2].outcome else {
            panic!("leg 2 concluded cancelled: {:?}", legs[2].outcome);
        };
        let LegFailure::Concluded { conclusion, .. } = failure else {
            panic!("leg 2 concluded cancelled: {failure:?}");
        };
        assert_eq!(conclusion, "cancelled");
        assert!(!leg_attempted(failure));
    }

    /// The page is the manifest: a leg whose jobs disagree on the
    /// hash is that leg's invariant failure even with no batch to
    /// check against.
    #[test]
    fn classify_page_still_catches_a_hash_mismatch() {
        let (_hash, build) = build_name(0, "task-a");
        let jobs = vec![
            job_row(build, Some("success"), vec![]),
            job_row(publish_name(0, "task-b"), Some("success"), vec![]),
        ];
        let legs = classify_page(&jobs, "success", at(1_000)).expect("classified");
        let LegOutcome::Failed(LegFailure::Invariant(message)) = &legs[0].outcome else {
            panic!(
                "a disagreeing hash is the leg's invariant: {:?}",
                legs[0].outcome
            );
        };
        assert!(message.contains("hash"));
    }

    /// A job name that is not a leg job fails the whole read — the
    /// run is ours, so an unreadable name is a schema surprise, never
    /// a leg to skip.
    #[test]
    fn classify_page_fails_on_a_non_leg_job() {
        let job = job_row("build-crate".to_owned(), Some("failure"), vec![]);
        assert!(classify_page(&[job], "failure", at(1_000)).is_err());
    }

    /// The jobs pager follows `Link: <…>; rel="next"`: a batch's jobs
    /// can outrun one `per_page=100` page, and both pages' rows must
    /// land in the answer. `test_server`'s steps cannot emit a `Link`
    /// header, so the fixture speaks HTTP/1.1 itself — a read of the
    /// request head, then the scripted response, connection closed.
    #[tokio::test]
    async fn fetch_jobs_pages_follows_link_next() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback binds");
        let addr = listener.local_addr().expect("bound");
        let base = format!("http://{addr}");
        let job = |id: u64| {
            format!(
                "{{\"id\":{id},\"name\":\"job {id}\",\"status\":\"completed\",\"conclusion\":\"success\",\"started_at\":null,\"completed_at\":null,\"run_attempt\":1,\"html_url\":\"\",\"steps\":[]}}"
            )
        };
        let respond = |link: Option<String>, id: u64| {
            let body = format!("{{\"jobs\":[{}]}}", job(id));
            let link = link.map_or(String::new(), |url| {
                format!("link: <{url}>; rel=\"next\"\r\n")
            });
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{link}content-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
        };
        let responses = [respond(Some(format!("{base}/page2")), 1), respond(None, 2)];
        let server = tokio::spawn(async move {
            for response in responses {
                let (mut socket, _) = listener.accept().await.expect("accept");
                let mut buffer = vec![0_u8; 4096];
                let mut head = Vec::new();
                loop {
                    let read = socket.read(&mut buffer).await.expect("read");
                    head.extend_from_slice(&buffer[..read]);
                    if head.windows(4).any(|w| w == b"\r\n\r\n") || read == 0 {
                        break;
                    }
                }
                socket
                    .write_all(response.as_bytes())
                    .await
                    .expect("write response");
            }
        });
        let jobs = super::fetch_jobs_pages(None, &format!("{base}/page1"))
            .await
            .expect("two pages of jobs");
        server.await.expect("server");
        assert_eq!(
            jobs.iter().map(|job| job.id).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }
}
