//! GitHub Actions run classification shared by `stow-admin` and the
//! scheduler Durable Object.
//!
//! [`classify_failure`] reads one run's jobs page and names why it
//! failed — the crate's verdict or runner infrastructure — and
//! [`classify_legs`] applies the same contract per leg of a
//! `build-batch.yml` run (stow#833).

use crate::api::TaskHash;
use crate::stow_error;

/// The clock allowance between a stow machine and GitHub.
///
/// A dispatch's wall time minus this is both a run-listing `created`
/// window start and the floor a candidate run's own `created_at` must
/// clear — GitHub's clock may trail ours by this much before a run the
/// dispatch created reads as older than its own attempt. The jobs-page
/// settle comparison in [`classify_failure`] grants it toward the
/// deferral so local-versus-GitHub skew can never read a
/// just-completed job as a lost runner.
pub const GITHUB_CLOCK_ALLOWANCE: time::Duration = time::Duration::seconds(60);

// ===== Step classification =====

/// The `build-crate.yml` step names whose failure is the crate's
/// verdict.
///
/// These are the steps that run the crate or judge its outputs; every
/// other step is runner setup, toolchain install or artifact transfer.
/// Step names are the contract: keep them in sync with
/// `.github/workflows/build-crate.yml`.
pub const VERDICT_STEPS: &[&str] = &[
    "Run the untrusted build stage",
    "Report the built outputs' glibc floor",
    "Run the trusted publish stage",
];
/// How long a failed job's unsettled step rows may still be settling.
///
/// A run reaching `completed` writes its step rows within seconds of
/// the job's own `completed_at`, while a runner that drops
/// communication leaves `in_progress`/`pending` step rows behind
/// forever (runs 38919684562 and 38410583752 — "The hosted runner lost
/// communication with the server"). Two minutes is far past every
/// observed settle, so after the window an unsettled failed job is the
/// lost-runner case and classifies `Infrastructure`.
pub const STEP_SETTLE_WINDOW: time::Duration = time::Duration::minutes(2);

/// A completed run's non-success conclusion, classified by which step
/// failed.
///
/// `Verdict` is the crate's own outcome — the failed step runs the
/// crate or judges its outputs; `Infrastructure` names the failed job
/// and step — runner setup, toolchain install or artifact transfer —
/// and earns a rerun of the run's failed jobs instead of the node's
/// verdict. A jobs page read mid-settle is not a class at all —
/// [`classify_failure`] holds it unsettled until the failed job's step
/// rows finish writing or outlive [`STEP_SETTLE_WINDOW`], past which
/// they name where the runner was lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunFailure {
    /// The crate's own outcome — the failed step runs the crate or
    /// judges its outputs.
    Verdict {
        /// The failed job's name.
        job: String,
        /// The failed `VERDICT_STEPS` step's name.
        step: String,
    },
    /// Runner infrastructure failed, not the crate.
    Infrastructure {
        /// The failed job's name — for the warn log and the report;
        /// `"-"` when no job ever failed (`startup_failure` — no runner
        /// took the run).
        job: String,
        /// Its first failed step — `None` when the runner was lost
        /// before any step ran (a cancelled setup, a dropped runner).
        step: Option<String>,
    },
}

/// A job or step row has settled once GitHub reports it `completed` —
/// a run's own `completed` arrives while its job rows still read
/// `queued`/`in_progress`/`waiting` and the failed job's steps the
/// same, so every other value is a page still being written.
fn row_completed(status: &str) -> bool {
    status == "completed"
}

/// Classify a completed failed run by its jobs as of `now`.
///
/// The first failed job's first failed step decides — a
/// `VERDICT_STEPS` step is the crate's verdict and anything else is
/// infrastructure. A failed job with no failed step (the runner died
/// mid-job) and a failed run with no failed job at all
/// (`startup_failure` — no runner ever took it) are infrastructure
/// too.
///
/// `None` is "no answer yet", not a class: GitHub lets a run reach
/// `completed` before its job and step rows do, and a page read
/// mid-settle shows the failed job without its failed step — the
/// lost-runner shape — so a verdict would misclassify as
/// infrastructure and earn a rerun GitHub then refuses (stow#765). A
/// job still not `completed` defers unconditionally; a failed job
/// whose step rows are unsettled defers only inside
/// [`STEP_SETTLE_WINDOW`] of its own `completed_at` — past the window
/// the first unsettled step is where the runner was lost, and the
/// class is `Infrastructure` naming it. `now` is the caller's clock:
/// the comparison grants [`GITHUB_CLOCK_ALLOWANCE`] toward the
/// deferral so local-versus-GitHub skew can never read a
/// just-completed job as a lost runner.
///
/// # Errors
/// A `completed` job row carrying no `completed_at` — a schema
/// surprise, so the classifier fails fast rather than guess at its
/// age.
pub fn classify_failure(
    jobs: &[RunJobRow],
    now: time::OffsetDateTime,
) -> crate::error::Result<Option<RunFailure>> {
    if jobs.iter().any(|job| !row_completed(&job.status)) {
        return Ok(None);
    }
    let Some(job) = jobs
        .iter()
        .find(|job| job.conclusion.as_deref() == Some("failure"))
    else {
        return Ok(Some(RunFailure::Infrastructure {
            job: "-".to_owned(),
            step: None,
        }));
    };
    if let Some(step) = job.steps.iter().find(|step| !row_completed(&step.status)) {
        let Some(completed_at) = job.completed_at else {
            return Err(stow_error!(
                "jobs page: completed job {:?} carries no completed_at",
                job.name
            ));
        };
        if now - completed_at < STEP_SETTLE_WINDOW + GITHUB_CLOCK_ALLOWANCE {
            return Ok(None);
        }
        return Ok(Some(RunFailure::Infrastructure {
            job: job.name.clone(),
            step: Some(step.name.clone()),
        }));
    }
    let Some(step) = job
        .steps
        .iter()
        .find(|step| step.conclusion.as_deref() == Some("failure"))
    else {
        return Ok(Some(RunFailure::Infrastructure {
            job: job.name.clone(),
            step: None,
        }));
    };
    if VERDICT_STEPS.contains(&step.name.as_str()) {
        Ok(Some(RunFailure::Verdict {
            job: job.name.clone(),
            step: step.name.clone(),
        }))
    } else {
        Ok(Some(RunFailure::Infrastructure {
            job: job.name.clone(),
            step: Some(step.name.clone()),
        }))
    }
}

// ===== GitHub REST shapes =====

/// `GET actions/runs/{id}/jobs` — each job's status and conclusion and
/// its steps'.
///
/// The endpoint serves the latest attempt's jobs by default, exactly
/// the attempt the run's `run_attempt` names.
#[derive(Debug, serde::Deserialize)]
pub struct RunJobsPage {
    /// The page's job rows.
    pub jobs: Vec<RunJobRow>,
}

/// One job row of a [`RunJobsPage`].
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RunJobRow {
    /// The job's id — the `jobs/{id}/logs` path segment.
    pub id: u64,
    /// The job's display name — the build job's carries
    /// `build <crate> <version> (<target>)`; a `build-batch.yml` leg's
    /// names follow [`LegJobName`].
    pub name: String,
    /// `queued`/`in_progress`/`completed`/`waiting`/`pending` as
    /// GitHub serves it — a run's `completed` arrives while its job
    /// rows are still settling, so classification reads it.
    pub status: String,
    /// `success`/`failure`/`skipped`/… — `None` while the job runs.
    #[serde(default)]
    pub conclusion: Option<String>,
    /// GitHub's start time — null until the job begins. A leg's runner
    /// time is measured from its build job's `started_at`.
    #[serde(with = "time::serde::rfc3339::option")]
    pub started_at: Option<time::OffsetDateTime>,
    /// GitHub's completion time — null until the job finishes. The
    /// lost-runner rule measures the failed job's unsettled step rows
    /// as [`STEP_SETTLE_WINDOW`] past it.
    #[serde(with = "time::serde::rfc3339::option")]
    pub completed_at: Option<time::OffsetDateTime>,
    /// Which attempt of the run the job belongs to — the leg outcome
    /// reads the publish job's, since a rerun's records land under a
    /// fresh tag.
    pub run_attempt: u32,
    /// The job's Actions URL — a leg record's pointer back to it.
    pub html_url: String,
    /// The job's step rows.
    pub steps: Vec<RunStepRow>,
}

/// One step row of a [`RunJobRow`].
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RunStepRow {
    /// The step's display name — the contract `VERDICT_STEPS` matches.
    pub name: String,
    /// The same settle contract the job row's `status` carries.
    pub status: String,
    /// The step's conclusion — `None` while it runs.
    #[serde(default)]
    pub conclusion: Option<String>,
}

/// `GET actions/runs/{id}` — the run's coarse state the lease check
/// reads (stow#833 §4.3).
///
/// `completed` resolves the batch as if its webhook had arrived;
/// `queued`/`in_progress` extends the lease; `run_attempt` pins the
/// jobs page to the attempt the scheduler dispatched.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RunStatus {
    /// `queued`/`in_progress`/`completed`/`waiting` as GitHub serves
    /// it.
    pub status: String,
    /// `success`/`failure`/`cancelled`/`startup_failure`/… — `None`
    /// while the run is not `completed`.
    #[serde(default)]
    pub conclusion: Option<String>,
    /// The run's current attempt — the `attempts/{n}/jobs` page the
    /// leg classifier reads.
    pub run_attempt: u32,
    /// The run's Actions URL — the leg failure's pointer back to it.
    pub html_url: String,
}

/// The `rel="next"` target of an RFC 8288 `Link` header — the
/// attempt-jobs pager's continuation (stow#833).
///
/// Each `<url>; rel="…"` link-param is comma-separated; GitHub serves
/// `next`/`last` while a page follows and `prev`/`first` alone on the
/// last page, so `None` — an absent header or no `next` link — ends
/// the walk.
#[must_use]
pub fn link_next(header: Option<&str>) -> Option<&str> {
    header?.split(',').find_map(|link| {
        let (url, params) = link.trim().strip_prefix('<')?.split_once('>')?;
        params
            .split(';')
            .map(str::trim)
            .any(|param| param.eq_ignore_ascii_case("rel=\"next\""))
            .then(|| url.trim())
    })
}

// ===== Leg classification (stow#833) =====

/// Which of a `build-batch.yml` leg's two `build-crate.yml` jobs a
/// job-name segment names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegJobKind {
    /// `build #<N> <label> (<target>) <16 hex>` — the untrusted stage.
    Build,
    /// `publish #<N> <16 hex>` — the trusted stage.
    Publish,
}

/// A `build-batch.yml` leg's job name, parsed (stow#833 §2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegJobName {
    /// Build or publish.
    pub kind: LegJobKind,
    /// The leg's index in the batch's `tasks` list — the `#N`.
    pub leg: u32,
    /// The leg's [`TaskHash`] — `blake3(task_id)`'s first 16 hex, the
    /// job-name binding that maps a run's jobs back to legs by hash,
    /// not by position alone.
    pub hash: TaskHash,
}

impl LegJobName {
    /// Parse a job name from a `build-batch.yml` run's jobs page.
    ///
    /// GitHub names a reusable-workflow matrix job
    /// `"<caller job> / <called job>"`, so the caller's `leg <i>`
    /// prefix is discarded at the last `" / "` (the whole name stands
    /// when no separator is present). The segment then reads
    /// `build #<N> <label> (<target>) <16 hex>` or
    /// `publish #<N> <16 hex>`.
    ///
    /// `None` when the segment matches neither shape — the caller
    /// fails fast on it, since the run is ours.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        let name = name.rsplit_once(" / ").map_or(name, |(_, called)| called);
        let (kind, rest) = name
            .strip_prefix("build #")
            .map(|rest| (LegJobKind::Build, rest))
            .or_else(|| {
                name.strip_prefix("publish #")
                    .map(|rest| (LegJobKind::Publish, rest))
            })?;
        let (leg, label) = rest.split_once(' ')?;
        if leg.is_empty() || !leg.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let leg = leg.parse().ok()?;
        let hash = match kind {
            // `publish #N <hash>` — the remainder is the hash alone.
            LegJobKind::Publish => label.parse().ok()?,
            // `build #N <label> (<target>) <hash>` — the hash is the
            // last space-separated token and the label must be
            // nonempty.
            LegJobKind::Build => {
                let (label, hash) = label.rsplit_once(' ')?;
                if label.is_empty() {
                    return None;
                }
                hash.parse().ok()?
            }
        };
        Some(Self { kind, leg, hash })
    }
}

/// Why a leg failed — the leg-resolution analogue of [`RunFailure`]
/// (stow#833 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegFailure {
    /// A job concluded `failure` — [`classify_failure`] on the leg's
    /// own jobs names verdict or infrastructure.
    Run(RunFailure),
    /// A job concluded `cancelled`/`timed_out`/`skipped` with none
    /// failed — the conclusion names the outcome.
    Concluded {
        /// The concluded job's name.
        job: String,
        /// Its conclusion (`cancelled`, `timed_out`, `skipped`, …).
        conclusion: String,
        /// The job's Actions URL.
        html_url: String,
    },
    /// The page contradicts the batch — a leg absent, a duplicate job
    /// for one leg, or a job hash that is not the leg's [`TaskHash`].
    /// The message names the mismatch.
    Invariant(String),
}

/// One batch leg's outcome as of a jobs-page read (stow#833 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegOutcome {
    /// Both jobs completed with conclusion `success`. The caller still
    /// confirms the leg's signed records artifact in GHCR before
    /// marking the task done.
    Succeeded {
        /// The build job's `started_at` — the leg's runner time opens
        /// here. A successful leg whose build job lacks it is an
        /// [`LegFailure::Invariant`], never a success with a missing
        /// duration edge.
        started_at: time::OffsetDateTime,
        /// The publish job's `completed_at` — the leg's runner time
        /// ends here. Missing, the leg is an [`LegFailure::Invariant`]
        /// like a build job without `started_at`.
        completed_at: time::OffsetDateTime,
        /// The publish job's `run_attempt` — the attempt whose records
        /// tag the caller checks.
        publish_attempt: u32,
    },
    /// The leg failed — [`LegFailure`] names the class.
    Failed(LegFailure),
    /// No answer yet: a job is not `completed`, or a failed job's step
    /// rows are still inside their settle window — the batch keeps its
    /// `resolve_after` and the next pass reads again.
    Unsettled,
}

/// A leg's jobs on the page, by [`LegJobKind`], plus the first job
/// hash that did not equal the leg's expected [`TaskHash`].
#[derive(Debug, Default)]
struct LegJobs {
    /// Page indexes of the leg's `build` jobs — more than one is a
    /// duplicate.
    build: Vec<usize>,
    /// Page indexes of the leg's `publish` jobs.
    publish: Vec<usize>,
    /// The first parsed hash that was not `expected[leg]`.
    hash_mismatch: Option<TaskHash>,
}

/// Classify every leg of a `build-batch.yml` run from its jobs page
/// and the run's own conclusion (stow#833 §4.1).
///
/// `expected[i]` is leg `i`'s [`TaskHash`] — `BatchTask::task_hash` of
/// the leg at `BuildBatchPayload::tasks[i]` — and `run_conclusion` the
/// run's reported conclusion. `now` is the caller's clock, granted
/// [`GITHUB_CLOCK_ALLOWANCE`] inside [`classify_failure`]. The result
/// holds one [`LegOutcome`] per expected leg, in leg order.
///
/// A run whose conclusion is `startup_failure` and whose page holds no
/// jobs fails every leg [`RunFailure::Infrastructure`] with no job —
/// no runner ever took it.
///
/// # Errors
/// A job name [`LegJobName::parse`] cannot read — the run is ours, so
/// a job that is not a leg is a schema surprise — or a leg index past
/// `expected.len()`: both are structural violations of the page, not
/// one leg's outcome.
pub fn classify_legs(
    expected: &[TaskHash],
    run_conclusion: &str,
    jobs: &[RunJobRow],
    now: time::OffsetDateTime,
) -> crate::error::Result<Vec<LegOutcome>> {
    if run_conclusion == "startup_failure" && jobs.is_empty() {
        return Ok(expected
            .iter()
            .map(|_| {
                LegOutcome::Failed(LegFailure::Run(RunFailure::Infrastructure {
                    job: "-".to_owned(),
                    step: None,
                }))
            })
            .collect());
    }
    let mut legs: Vec<LegJobs> = (0..expected.len()).map(|_| LegJobs::default()).collect();
    for (index, job) in jobs.iter().enumerate() {
        let Some(parsed) = LegJobName::parse(&job.name) else {
            return Err(stow_error!(
                "batch run jobs page names a non-leg job {:?}",
                job.name
            ));
        };
        let leg = usize::try_from(parsed.leg).map_err(|error| stow_error!("{error}"))?;
        let Some(entry) = legs.get_mut(leg) else {
            return Err(stow_error!(
                "batch run jobs page names leg {} — the batch holds {} legs",
                parsed.leg,
                expected.len()
            ));
        };
        if parsed.hash != expected[leg] && entry.hash_mismatch.is_none() {
            entry.hash_mismatch = Some(parsed.hash);
        }
        match parsed.kind {
            LegJobKind::Build => entry.build.push(index),
            LegJobKind::Publish => entry.publish.push(index),
        }
    }
    expected
        .iter()
        .enumerate()
        .map(|(leg, expected_hash)| classify_leg(leg, expected_hash, &legs[leg], jobs, now))
        .collect()
}

/// One leg's outcome — the page's build/publish pair (or its absence)
/// against the settle contract.
fn classify_leg(
    leg: usize,
    expected_hash: &TaskHash,
    entry: &LegJobs,
    jobs: &[RunJobRow],
    now: time::OffsetDateTime,
) -> crate::error::Result<LegOutcome> {
    if entry.build.is_empty() && entry.publish.is_empty() {
        return Ok(LegOutcome::Failed(LegFailure::Invariant(format!(
            "leg {leg} has no jobs on the page"
        ))));
    }
    if let Some(found) = &entry.hash_mismatch {
        return Ok(LegOutcome::Failed(LegFailure::Invariant(format!(
            "leg {leg}'s job carries hash {found} — the batch's leg carries {expected_hash}"
        ))));
    }
    if entry.build.len() > 1 || entry.publish.len() > 1 {
        return Ok(LegOutcome::Failed(LegFailure::Invariant(format!(
            "leg {leg} has {} build and {} publish jobs on the page — a leg runs one of each",
            entry.build.len(),
            entry.publish.len()
        ))));
    }
    let build = entry.build.first().map(|&index| &jobs[index]);
    let publish = entry.publish.first().map(|&index| &jobs[index]);
    let present: Vec<&RunJobRow> = [build, publish].into_iter().flatten().collect();
    if present
        .iter()
        .any(|job| job.conclusion.as_deref() == Some("failure"))
    {
        let rows: Vec<RunJobRow> = present.iter().map(|job| (*job).clone()).collect();
        return Ok(
            classify_failure(&rows, now)?.map_or(LegOutcome::Unsettled, |failure| {
                LegOutcome::Failed(LegFailure::Run(failure))
            }),
        );
    }
    if present.iter().any(|job| !row_completed(&job.status)) {
        return Ok(LegOutcome::Unsettled);
    }
    let concluded = |job: &RunJobRow| -> LegOutcome {
        job.conclusion.as_ref().map_or_else(
            || {
                LegOutcome::Failed(LegFailure::Invariant(format!(
                    "leg {leg}'s job {:?} completed with no conclusion",
                    job.name
                )))
            },
            |conclusion| {
                LegOutcome::Failed(LegFailure::Concluded {
                    job: job.name.clone(),
                    conclusion: conclusion.clone(),
                    html_url: job.html_url.clone(),
                })
            },
        )
    };
    // Every present job completed and none failed — a success is the
    // pair both reading `success`; anything else names the first
    // non-success job's conclusion.
    let culprit = [build, publish]
        .into_iter()
        .flatten()
        .find(|job| job.conclusion.as_deref() != Some("success"));
    Ok(match (build, publish) {
        (None, None) => unreachable!("a leg with no jobs is an invariant above"),
        (None, Some(_)) => LegOutcome::Failed(LegFailure::Invariant(format!(
            "leg {leg} has a publish job on the page but no build job"
        ))),
        // The build leg succeeded; its publish row has not landed yet.
        (Some(_), None) if culprit.is_none() => LegOutcome::Unsettled,
        (Some(_), None) => concluded(build.expect("build leg present")),
        (Some(build), Some(publish)) if culprit.is_none() => {
            match (build.started_at, publish.completed_at) {
                (Some(started_at), Some(completed_at)) => LegOutcome::Succeeded {
                    started_at,
                    completed_at,
                    publish_attempt: publish.run_attempt,
                },
                (None, _) => LegOutcome::Failed(LegFailure::Invariant(format!(
                    "leg {leg}'s build job {:?} completed `success` with no started_at",
                    build.name
                ))),
                (_, None) => LegOutcome::Failed(LegFailure::Invariant(format!(
                    "leg {leg}'s publish job {:?} completed `success` with no completed_at",
                    publish.name
                ))),
            }
        }
        (Some(_), Some(_)) => concluded(culprit.expect("a non-success job exists")),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        LegFailure, LegJobKind, LegJobName, LegOutcome, RunFailure, RunJobRow, RunStepRow,
        TaskHash, VERDICT_STEPS, classify_failure, classify_legs,
    };
    use time::OffsetDateTime;

    /// A wall-clock timestamp for the classifier fixtures.
    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).expect("timestamp")
    }

    /// One jobs row for the classifier — `status` is the job's own and
    /// each step is `(name, status, conclusion)`. A settled page
    /// reports `completed` everywhere; anything else is GitHub still
    /// writing it.
    fn job_row(
        name: &str,
        status: &str,
        conclusion: Option<&str>,
        completed_at: Option<i64>,
        steps: &[(&str, &str, Option<&str>)],
    ) -> RunJobRow {
        RunJobRow {
            id: 0,
            name: name.to_owned(),
            status: status.to_owned(),
            conclusion: conclusion.map(str::to_owned),
            started_at: None,
            completed_at: completed_at.map(at),
            run_attempt: 1,
            html_url: String::new(),
            steps: steps
                .iter()
                .map(|&(name, status, conclusion)| RunStepRow {
                    name: name.to_owned(),
                    status: status.to_owned(),
                    conclusion: conclusion.map(str::to_owned),
                })
                .collect(),
        }
    }

    /// A failed step named by `VERDICT_STEPS` is the crate's verdict —
    /// the build stage, the glibc-floor report and the publish stage.
    #[test]
    fn a_verdict_step_is_final() {
        for step in VERDICT_STEPS {
            let jobs = [job_row(
                "build",
                "completed",
                Some("failure"),
                Some(1_000_000),
                &[(*step, "completed", Some("failure"))],
            )];
            assert!(
                matches!(
                    classify_failure(&jobs, at(1_000_100)),
                    Ok(Some(RunFailure::Verdict { .. }))
                ),
                "{step} is the crate's verdict"
            );
        }
    }

    /// The step run 38019734143 died in — the toolchain install — is
    /// runner infrastructure, not the crate's verdict.
    #[test]
    fn a_setup_step_failure_is_infrastructure() {
        const TOOLCHAIN_STEP: &str =
            "Run dtolnay/rust-toolchain@02cb101ec7c40f2c49e1d9714d64511d8e1b74de";
        let jobs = [job_row(
            "build adler2 2.0.1 (aarch64-linux-android)",
            "completed",
            Some("failure"),
            Some(1_000_000),
            &[(TOOLCHAIN_STEP, "completed", Some("failure"))],
        )];
        let Ok(Some(RunFailure::Infrastructure { job, step })) =
            classify_failure(&jobs, at(1_000_100))
        else {
            panic!("a toolchain-install failure is infrastructure");
        };
        assert_eq!(step.as_deref(), Some(TOOLCHAIN_STEP));
        assert!(job.contains("adler2"));
    }

    /// A failed job with no failed step — the runner was lost before a
    /// step could fail — is infrastructure; so is a failed run with no
    /// failed job at all (`startup_failure`). Both hold only on a
    /// settled page.
    #[test]
    fn a_failed_job_with_no_failed_step_is_infrastructure() {
        let jobs = [job_row(
            "build",
            "completed",
            Some("failure"),
            Some(1_000_000),
            &[("Check out the repository", "completed", Some("success"))],
        )];
        assert!(matches!(
            classify_failure(&jobs, at(1_000_100)),
            Ok(Some(RunFailure::Infrastructure { step: None, .. }))
        ));
        assert!(matches!(
            classify_failure(&[], at(1_000_100)),
            Ok(Some(RunFailure::Infrastructure { step: None, .. }))
        ));
    }

    /// stow#765: the settled read of run 38936251869 — the failed job's
    /// failing step is a `VERDICT_STEPS` step, so the failure is the
    /// crate's verdict and no rerun is asked.
    #[test]
    fn a_settled_verdict_step_failure_is_the_crates_verdict() {
        let jobs = [job_row(
            "build foundationdb-gen 0.11.0 (aarch64-unknown-linux-gnu)",
            "completed",
            Some("failure"),
            Some(1_000_000),
            &[
                ("Check out the repository", "completed", Some("success")),
                (
                    "Run the untrusted build stage",
                    "completed",
                    Some("failure"),
                ),
            ],
        )];
        assert!(matches!(
            classify_failure(&jobs, at(1_000_100)),
            Ok(Some(RunFailure::Verdict { .. }))
        ));
    }

    /// stow#765: run 38936251869 read mid-settle — the failed job's row
    /// has landed but the step it failed in still says `in_progress`
    /// with no conclusion. Inside `STEP_SETTLE_WINDOW` of the job's
    /// `completed_at` the page defers rather than read as the
    /// lost-runner shape and rerun a verdict.
    #[test]
    fn a_failed_job_settling_inside_the_window_defers() {
        let jobs = [job_row(
            "build foundationdb-gen 0.11.0 (aarch64-unknown-linux-gnu)",
            "completed",
            Some("failure"),
            Some(1_000_000 - 30),
            &[
                ("Check out the repository", "completed", Some("success")),
                ("Run the untrusted build stage", "in_progress", None),
            ],
        )];
        assert!(
            classify_failure(&jobs, at(1_000_000))
                .expect("classified")
                .is_none()
        );
    }

    /// stow#765: run 38919684562's shape — a lost runner leaves the
    /// failed job's `in_progress`/`pending` step rows unsettled
    /// forever. Past `STEP_SETTLE_WINDOW` the first unsettled step is
    /// where the runner was lost: infrastructure, naming it.
    #[test]
    fn a_lost_runners_unsettled_steps_are_infrastructure_past_the_window() {
        let jobs = [
            job_row(
                "build",
                "completed",
                Some("success"),
                Some(1_000_000 - 900),
                &[("Check out the repository", "completed", Some("success"))],
            ),
            job_row(
                "publish",
                "completed",
                Some("failure"),
                Some(1_000_000 - 600),
                &[
                    ("Check out the repository", "completed", Some("success")),
                    ("Publish the built index slice", "in_progress", None),
                    ("Post the run summary", "pending", None),
                ],
            ),
        ];
        let Ok(Some(RunFailure::Infrastructure { job, step })) =
            classify_failure(&jobs, at(1_000_000))
        else {
            panic!("a lost runner is infrastructure");
        };
        assert_eq!(job, "publish");
        assert_eq!(step.as_deref(), Some("Publish the built index slice"));
    }

    /// A `completed` job always carries `completed_at` — one without it
    /// is a schema surprise, and the classifier fails fast rather than
    /// guess at its age.
    #[test]
    fn a_completed_failed_job_without_completed_at_fails() {
        let jobs = [job_row(
            "build",
            "completed",
            Some("failure"),
            None,
            &[("Run the untrusted build stage", "in_progress", None)],
        )];
        assert!(classify_failure(&jobs, at(1_000_000)).is_err());
    }

    /// A page whose job rows are not all `completed` defers too — even
    /// one that already shows a verdict step, because a run's own
    /// `completed` arrives before its job rows finish.
    #[test]
    fn a_page_with_a_job_still_running_defers() {
        let jobs = [
            job_row(
                "build a",
                "completed",
                Some("failure"),
                Some(1_000_000 - 600),
                &[(
                    "Run the untrusted build stage",
                    "completed",
                    Some("failure"),
                )],
            ),
            job_row("build b", "in_progress", None, None, &[]),
        ];
        assert!(
            classify_failure(&jobs, at(1_000_000))
                .expect("classified")
                .is_none()
        );
    }

    // ----- Leg classification (stow#833) -----

    /// Leg `i`'s expected [`TaskHash`] — deterministic per fixture.
    fn leg_hash(leg: u32) -> TaskHash {
        TaskHash::of(&format!("task-{leg}"))
    }

    /// Leg `i`'s `kind` job name as GitHub reports it — caller-job
    /// prefix and called-job segment together.
    fn leg_name(kind: LegJobKind, leg: u32, hash: &TaskHash) -> String {
        let called = match kind {
            LegJobKind::Build => {
                format!("build #{leg} serde 1.0.0 (x86_64-unknown-linux-gnu) {hash}")
            }
            LegJobKind::Publish => format!("publish #{leg} {hash}"),
        };
        format!("leg {leg} / {called}")
    }

    /// One leg job row, with the timestamps and url the leg outcome
    /// reads.
    fn leg_job(
        kind: LegJobKind,
        leg: u32,
        hash: &TaskHash,
        status: &str,
        conclusion: Option<&str>,
        steps: &[(&str, &str, Option<&str>)],
    ) -> RunJobRow {
        let mut row = job_row(
            &leg_name(kind, leg, hash),
            status,
            conclusion,
            Some(100),
            steps,
        );
        row.started_at = Some(at(50));
        row.html_url = format!("https://github.com/water-rs/stow/actions/runs/1/job/{leg}");
        row
    }

    /// Both of leg `i`'s jobs completed `success`.
    fn settled_leg(leg: u32) -> [RunJobRow; 2] {
        [
            leg_job(
                LegJobKind::Build,
                leg,
                &leg_hash(leg),
                "completed",
                Some("success"),
                &[],
            ),
            leg_job(
                LegJobKind::Publish,
                leg,
                &leg_hash(leg),
                "completed",
                Some("success"),
                &[],
            ),
        ]
    }

    /// A leg reads as `build #N <label> (<target>) <hash>` /
    /// `publish #N <hash>` under the caller-job prefix — and the same
    /// segment alone, when GitHub drops the `"leg N / "` prefix.
    #[test]
    fn leg_job_names_parse_with_and_without_the_caller_prefix() {
        let hash = leg_hash(3);
        for name in [
            leg_name(LegJobKind::Build, 3, &hash),
            format!("build #3 serde 1.0.0 (x86_64-unknown-linux-gnu) {hash}"),
        ] {
            let parsed = LegJobName::parse(&name).expect("build name parses");
            assert_eq!(parsed.kind, LegJobKind::Build);
            assert_eq!(parsed.leg, 3);
            assert_eq!(parsed.hash, hash);
        }
        for name in [
            leg_name(LegJobKind::Publish, 3, &hash),
            format!("publish #3 {hash}"),
        ] {
            let parsed = LegJobName::parse(&name).expect("publish name parses");
            assert_eq!(parsed.kind, LegJobKind::Publish);
            assert_eq!(parsed.leg, 3);
            assert_eq!(parsed.hash, hash);
        }
    }

    /// Anything that is not `<kind> #<digits> … <16 lowercase hex>` is
    /// not a leg job.
    #[test]
    fn leg_job_names_refuse_malformed_shapes() {
        let hash = leg_hash(3);
        for name in [
            // Not a leg shape at all.
            "leg 3",
            "build-crate",
            "resolve-a1-req-serde",
            // No `#N`.
            &format!("build serde 1.0.0 {hash}"),
            // A non-decimal leg index.
            &format!("build #x serde 1.0.0 (x86_64) {hash}"),
            &format!("publish #3a {hash}"),
            // Missing or misplaced hash.
            "build #3 serde 1.0.0 (x86_64-unknown-linux-gnu)",
            &format!("publish #3 (x86_64) {hash}"),
            &format!("publish #{hash} 3"),
            // A hash that is not exactly 16 lowercase hex.
            "build #3 serde 1.0.0 (x86_64) 0123456789abcde",
            "build #3 serde 1.0.0 (x86_64) 0123456789ABCDEF",
            &format!("publish #3 {hash}x"),
            // A publish name carrying a label — `publish #N <hash>`
            // only.
            &format!("publish #3 serde {hash}"),
            // A build name with nothing between `#N` and the hash.
            &format!("build #3 {hash}"),
        ] {
            assert_eq!(LegJobName::parse(name), None, "{name}");
        }
    }

    /// §4.1: both jobs completed `success` — the outcome carries the
    /// build's start, the publish's end and its attempt.
    #[test]
    fn a_settled_leg_succeeds() {
        let jobs = settled_leg(0);
        let outcomes =
            classify_legs(&[leg_hash(0)], "success", &jobs, at(1_000)).expect("classified");
        assert_eq!(
            outcomes,
            [LegOutcome::Succeeded {
                started_at: at(50),
                completed_at: at(100),
                publish_attempt: 1,
            }]
        );
    }

    /// A successful leg's duration edges come from real timestamps: a
    /// build job reporting `success` with no `started_at`, or a
    /// publish job with no `completed_at`, is that leg's invariant
    /// failure — the message names the job — never a success with a
    /// fabricated duration.
    #[test]
    fn a_settled_leg_missing_timestamps_is_an_invariant() {
        for (job, field) in [
            (LegJobKind::Build, "started_at"),
            (LegJobKind::Publish, "completed_at"),
        ] {
            let mut jobs = settled_leg(0).to_vec();
            match job {
                LegJobKind::Build => jobs[0].started_at = None,
                LegJobKind::Publish => jobs[1].completed_at = None,
            }
            let outcomes =
                classify_legs(&[leg_hash(0)], "success", &jobs, at(1_000)).expect("classified");
            let LegOutcome::Failed(LegFailure::Invariant(message)) = &outcomes[0] else {
                panic!("a missing {field} is the leg's invariant failure");
            };
            assert!(message.contains(&jobs[usize::from(job == LegJobKind::Publish)].name));
            assert!(message.contains(field));
        }
    }

    /// §4.1: a failed `VERDICT_STEPS` step on the leg's own jobs is the
    /// crate's verdict.
    #[test]
    fn a_leg_verdict_failure_is_a_run_failure() {
        let mut jobs = settled_leg(0).to_vec();
        jobs[0] = leg_job(
            LegJobKind::Build,
            0,
            &leg_hash(0),
            "completed",
            Some("failure"),
            &[(
                "Run the untrusted build stage",
                "completed",
                Some("failure"),
            )],
        );
        let outcomes =
            classify_legs(&[leg_hash(0)], "failure", &jobs, at(1_000)).expect("classified");
        assert!(
            matches!(
                outcomes[0],
                LegOutcome::Failed(LegFailure::Run(RunFailure::Verdict { .. }))
            ),
            "{:?}",
            outcomes[0]
        );
    }

    /// §4.1: a failure outside `VERDICT_STEPS` is infrastructure.
    #[test]
    fn a_leg_infrastructure_failure_is_a_run_failure() {
        let mut jobs = settled_leg(0).to_vec();
        jobs[0] = leg_job(
            LegJobKind::Build,
            0,
            &leg_hash(0),
            "completed",
            Some("failure"),
            &[("Set up the runner", "completed", Some("failure"))],
        );
        let outcomes =
            classify_legs(&[leg_hash(0)], "failure", &jobs, at(1_000)).expect("classified");
        assert!(
            matches!(
                outcomes[0],
                LegOutcome::Failed(LegFailure::Run(RunFailure::Infrastructure { .. }))
            ),
            "{:?}",
            outcomes[0]
        );
    }

    /// §4.1: `cancelled`/`timed_out`/`skipped` with none failed names
    /// the concluded job, its conclusion and its url.
    #[test]
    fn a_leg_concluded_without_a_failure_names_the_job() {
        let mut jobs = settled_leg(0).to_vec();
        jobs[0].conclusion = Some("cancelled".to_owned());
        jobs[1].conclusion = Some("skipped".to_owned());
        let outcomes =
            classify_legs(&[leg_hash(0)], "cancelled", &jobs, at(1_000)).expect("classified");
        assert_eq!(
            outcomes[0],
            LegOutcome::Failed(LegFailure::Concluded {
                job: jobs[0].name.clone(),
                conclusion: "cancelled".to_owned(),
                html_url: jobs[0].html_url.clone(),
            })
        );
    }

    /// §4.1: a job not yet `completed` defers the leg — the build can
    /// also be settled while its publish row has not landed.
    #[test]
    fn a_leg_with_a_job_still_running_is_unsettled() {
        let mut jobs = settled_leg(0).to_vec();
        jobs[1].status = "in_progress".to_owned();
        jobs[1].conclusion = None;
        let outcomes =
            classify_legs(&[leg_hash(0)], "in_progress", &jobs, at(1_000)).expect("classified");
        assert_eq!(outcomes, [LegOutcome::Unsettled]);

        // Build done, publish row absent — GitHub has not created it.
        let jobs = [leg_job(
            LegJobKind::Build,
            0,
            &leg_hash(0),
            "completed",
            Some("success"),
            &[],
        )];
        let outcomes =
            classify_legs(&[leg_hash(0)], "in_progress", &jobs, at(1_000)).expect("classified");
        assert_eq!(outcomes, [LegOutcome::Unsettled]);
    }

    /// §4.1: a failed leg whose step rows are still inside the settle
    /// window defers too.
    #[test]
    fn a_failed_leg_settling_inside_the_window_is_unsettled() {
        let mut jobs = settled_leg(0).to_vec();
        jobs[0] = leg_job(
            LegJobKind::Build,
            0,
            &leg_hash(0),
            "completed",
            Some("failure"),
            &[("Run the untrusted build stage", "in_progress", None)],
        );
        jobs[0].completed_at = Some(at(970));
        // The publish job rows as `skipped` — it never ran.
        jobs[1].conclusion = Some("skipped".to_owned());
        let outcomes =
            classify_legs(&[leg_hash(0)], "failure", &jobs, at(1_000)).expect("classified");
        assert_eq!(outcomes, [LegOutcome::Unsettled]);
    }

    /// §4.1: `startup_failure` with no jobs fails every leg as
    /// infrastructure — no runner ever took it.
    #[test]
    fn a_startup_failure_run_fails_every_leg() {
        let expected = [leg_hash(0), leg_hash(1)];
        let outcomes =
            classify_legs(&expected, "startup_failure", &[], at(1_000)).expect("classified");
        assert_eq!(
            outcomes,
            [
                LegOutcome::Failed(LegFailure::Run(RunFailure::Infrastructure {
                    job: "-".to_owned(),
                    step: None,
                })),
                LegOutcome::Failed(LegFailure::Run(RunFailure::Infrastructure {
                    job: "-".to_owned(),
                    step: None,
                })),
            ]
        );
    }

    /// §4.1: a leg absent from the page, a duplicate job for one leg,
    /// and a job hash that is not the leg's are that leg's invariant
    /// failure — the message names the mismatch.
    #[test]
    fn leg_invariants_fail_their_leg() {
        let expected = [leg_hash(0), leg_hash(1), leg_hash(2)];
        // Leg 0 absent; leg 1 holds a duplicate build job; leg 2's job
        // carries another leg's hash.
        let mut jobs = settled_leg(1).to_vec();
        jobs.push(leg_job(
            LegJobKind::Build,
            1,
            &leg_hash(1),
            "completed",
            Some("success"),
            &[],
        ));
        jobs.extend(settled_leg(2));
        jobs[3].name = leg_name(LegJobKind::Build, 2, &leg_hash(9));
        let outcomes = classify_legs(&expected, "failure", &jobs, at(1_000)).expect("classified");
        let [absent, duplicate, mismatched] = outcomes.try_into().expect("three legs");
        assert!(matches!(
            absent,
            LegOutcome::Failed(LegFailure::Invariant(ref message)) if message.contains("no jobs")
        ));
        assert!(matches!(
            duplicate,
            LegOutcome::Failed(LegFailure::Invariant(ref message)) if message.contains("2 build")
        ));
        let LegOutcome::Failed(LegFailure::Invariant(message)) = mismatched else {
            panic!("a hash mismatch is the leg's invariant failure");
        };
        assert!(message.contains(&leg_hash(9).to_string()));
        assert!(message.contains(&leg_hash(2).to_string()));
    }

    /// §4.1: a leg index past the batch — the run claims a leg the
    /// batch never dispatched — is structural, not one leg's outcome.
    #[test]
    fn a_leg_index_past_the_batch_fails_the_read() {
        let mut jobs = settled_leg(0).to_vec();
        jobs.extend(settled_leg(1));
        assert!(classify_legs(&[leg_hash(0)], "failure", &jobs, at(1_000)).is_err());
    }

    /// §4.1: a job name that is not a leg job fails the read — the run
    /// is ours, so a non-leg name is a schema surprise.
    #[test]
    fn a_non_leg_job_fails_the_read() {
        let mut jobs = settled_leg(0).to_vec();
        jobs.push(job_row(
            "Post the run summary",
            "completed",
            Some("success"),
            Some(100),
            &[],
        ));
        assert!(classify_legs(&[leg_hash(0)], "failure", &jobs, at(1_000)).is_err());
    }

    /// The pager's three page shapes: a middle page links `next` (the
    /// walk continues at that URL verbatim), the last page links only
    /// `prev`/`first` (None ends it), and an absent header ends it
    /// before either is read.
    #[test]
    fn link_next_follows_only_rel_next() {
        let next =
            "https://api.github.com/repos/o/r/actions/runs/1/attempts/2/jobs?per_page=100&page=2";
        let middle = format!(
            "<{next}>; rel=\"next\", \
             <https://api.github.com/x?page=9>; rel=\"last\""
        );
        assert_eq!(super::link_next(Some(&middle)), Some(next));
        let last =
            "<https://api.github.com/x?page=1>; rel=\"prev\", <https://api.github.com/x>; rel=\"first\"";
        assert_eq!(super::link_next(Some(last)), None);
        assert_eq!(super::link_next(None), None);
        assert_eq!(super::link_next(Some("")), None);
        // A `next` that is not the first link-param still resolves.
        let reordered =
            format!("<https://api.github.com/x?page=9>; rel=\"last\", <{next}>; rel=\"next\"");
        assert_eq!(super::link_next(Some(&reordered)), Some(next));
    }

    /// The run-status wire shape decodes the fields the lease check
    /// reads; a body missing one fails at the boundary.
    #[test]
    fn run_status_decodes_the_lease_fields() {
        let status: super::RunStatus = serde_json::from_str(
            r#"{"status":"completed","conclusion":"success","run_attempt":2,
               "html_url":"https://github.com/water-rs/stow/actions/runs/1",
               "extra":"ignored"}"#,
        )
        .expect("run status decodes");
        assert_eq!(status.status, "completed");
        assert_eq!(status.conclusion.as_deref(), Some("success"));
        assert_eq!(status.run_attempt, 2);
        for body in [
            r#"{"conclusion":"success","run_attempt":2,"html_url":"u"}"#,
            r#"{"status":"completed","run_attempt":"2","html_url":"u"}"#,
        ] {
            assert!(serde_json::from_str::<super::RunStatus>(body).is_err());
        }
    }
}
