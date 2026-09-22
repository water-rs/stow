//! `stow-admin runs failures --since <duration>` — fetch failed
//! `build-crate.yml` runs from GitHub Actions, pull each failed job's
//! log, classify the failure, and group by class.

use std::fmt::Write as _;

use clap::{Args, Subcommand};
use stow_types::stow_error;

use crate::github::{self, BUILD_WORKFLOW};
use crate::render::{self, Output, Table};

#[derive(Args)]
pub struct RunsArgs {
    #[command(subcommand)]
    pub command: RunsCommand,
}

#[derive(Subcommand)]
pub enum RunsCommand {
    /// List failed build-crate runs in the window, grouped by the failure
    /// class their job logs show.
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
    /// The edge rejected `artifacts/register` or `/complete`.
    RegisterRejected,
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
    const fn as_str(self) -> &'static str {
        match self {
            Self::ToolchainTargetMissing => "toolchain-target-missing",
            Self::CratesIoDownload => "crates-io-download",
            Self::GitDependencyOffline => "git-dependency-offline",
            Self::RegisterRejected => "register-rejected",
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
/// register → plan. The first error line that classifies wins the run.
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
    // The edge's register/complete rejections — stow-build's
    // `edge admin register rejected records` and the workflow's
    // `scheduler rejected completion report`.
    if line.contains("register rejected")
        || line.contains("artifacts/register")
        || line.contains("scheduler rejected completion report")
    {
        return Some(FailureClass::RegisterRejected);
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

/// Whether a log line reads as an error: GitHub's `##[error]` annotation
/// or a leading rust/cargo `error[…]`/`error:`.
fn is_error_line(line: &str) -> bool {
    line.contains("##[error]")
        || line.contains("::error::")
        || line.trim_start().starts_with("error")
}

/// Classify one job log. Scans error lines top-down for a known class;
/// when none match, a run whose log never shows the `stow-build build`
/// step starting died before the wrapper executed — the runner-loss and
/// setup-failure bucket.
fn classify_log(log: &str) -> (FailureClass, Option<String>) {
    for line in log.lines() {
        let line = without_log_timestamp(line);
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

// ===== GitHub REST shapes =====

#[derive(Debug, serde::Deserialize)]
struct WorkflowRunsPage {
    workflow_runs: Vec<WorkflowRun>,
}

#[derive(Debug, serde::Deserialize)]
struct WorkflowRun {
    id: u64,
    html_url: String,
}

#[derive(Debug, serde::Deserialize)]
struct JobsPage {
    jobs: Vec<Job>,
}

#[derive(Debug, serde::Deserialize)]
struct Job {
    id: u64,
    name: String,
    #[serde(default)]
    conclusion: Option<String>,
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
    runs: usize,
    examples: Vec<FailureExample>,
}

/// The `runs failures` payload.
#[derive(Debug, serde::Serialize)]
struct FailuresReport {
    workflow: &'static str,
    since_seconds: u64,
    failed_runs: usize,
    groups: Vec<FailureGroup>,
}

pub async fn run(token: &str, args: RunsArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        RunsCommand::Failures(args) => failures(token, args, output).await,
    }
}

/// Page through the workflow's failed runs since `since`.
async fn fetch_failed_runs(
    token: &str,
    since: std::time::Duration,
) -> stow_types::error::Result<Vec<WorkflowRun>> {
    // GitHub's `created` filter accepts `>=` an ISO timestamp.
    let cutoff = time::OffsetDateTime::now_utc() - since;
    let cutoff_text = cutoff
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| stow_error!("format --since cutoff: {error}"))?;
    let mut runs = Vec::new();
    let mut page = 1u32;
    loop {
        let page_runs: WorkflowRunsPage = github::get(
            token,
            &format!(
                "actions/workflows/{BUILD_WORKFLOW}/runs?status=failure&created=%3E%3D{cutoff_text}&per_page=100&page={page}"
            ),
        )
        .await?;
        let count = page_runs.workflow_runs.len();
        runs.extend(page_runs.workflow_runs);
        if count < 100 {
            break;
        }
        page += 1;
    }
    Ok(runs)
}

/// Fetch each failed job's log and group the classified failures.
async fn classify_runs(
    token: &str,
    runs: &[WorkflowRun],
) -> stow_types::error::Result<Vec<FailureGroup>> {
    let mut groups: std::collections::BTreeMap<FailureClass, Vec<FailureExample>> =
        std::collections::BTreeMap::new();
    for run in runs {
        let jobs: JobsPage =
            github::get(token, &format!("actions/runs/{}/jobs?per_page=100", run.id)).await?;
        for job in &jobs.jobs {
            if job.conclusion.as_deref() != Some("failure") {
                continue;
            }
            let log_url = format!(
                "https://api.github.com/repos/{}/actions/jobs/{}/logs",
                github::REPO,
                job.id
            );
            let log = match github::get_text(token, &log_url).await {
                Ok(log) => log,
                Err(error) => {
                    tracing::warn!(job_id = job.id, %error, "job log unavailable; skipping");
                    continue;
                }
            };
            let (class, evidence) = classify_log(&log);
            groups.entry(class).or_default().push(FailureExample {
                run_url: run.html_url.clone(),
                job: job.name.clone(),
                evidence,
            });
        }
    }
    Ok(groups
        .into_iter()
        .map(|(class, examples)| FailureGroup {
            class,
            runs: examples.len(),
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

    let report = FailuresReport {
        workflow: BUILD_WORKFLOW,
        since_seconds: args.since.as_secs(),
        failed_runs: runs.len(),
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
            report.failed_runs,
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
                group.runs.to_string(),
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
    use super::{FailureClass, classify_log};

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
    fn classifies_register_rejected() {
        let log = "##[error]edge admin register rejected records: HTTP 403 forbidden\n";
        assert_eq!(classify_log(log).0, FailureClass::RegisterRejected);
    }

    #[test]
    fn classifies_plan_validation() {
        let log = "error: planned artifact ghcr.io/x claims crate serde 1.0.0, which is not in the resolved closure of y 2.0 (3 packages)\n";
        assert_eq!(classify_log(log).0, FailureClass::PlanValidation);
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
}
