//! GitHub Actions run classification shared by `stow-admin` and the
//! scheduler Durable Object.
//!
//! [`classify_failure`] reads one run's jobs page and names why it
//! failed — the crate's verdict or runner infrastructure.

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
        /// The failed job's Actions URL.
        html_url: String,
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
        /// The failed job's Actions URL — empty when `job` is `"-"`:
        /// a run with no job at all has no job URL to carry.
        html_url: String,
    },
}

/// A step row has settled once GitHub reports it `completed` — a
/// run's own `completed` arrives while its step rows still read
/// `queued`/`in_progress`/`waiting`, so every other value is a page
/// still being written. Job rows settle wider — see [`job_settled`].
fn row_completed(status: &str) -> bool {
    status == "completed"
}

/// A job row is settled once GitHub reports it `completed` — or the
/// moment it carries a `conclusion`, which is only ever written on a
/// finished job: a completed run's job row can still read
/// `in_progress` with its `conclusion` already set (run 39842358378,
/// stow#863), and the conclusion is the truer word.
fn job_settled(job: &RunJobRow) -> bool {
    job.conclusion.is_some() || row_completed(&job.status)
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
/// job still not settled — neither `completed` nor carrying a
/// `conclusion` (stow#863) — defers unconditionally; a failed job
/// whose step rows are unsettled defers only inside
/// [`STEP_SETTLE_WINDOW`] of its own `completed_at` — past the window
/// the first unsettled step is where the runner was lost, and the
/// class is `Infrastructure` naming it. `now` is the caller's clock:
/// the comparison grants [`GITHUB_CLOCK_ALLOWANCE`] toward the
/// deferral so local-versus-GitHub skew can never read a
/// just-completed job as a lost runner.
///
/// # Errors
/// A settled job row carrying no `completed_at` — a schema
/// surprise, so the classifier fails fast rather than guess at its
/// age.
pub fn classify_failure(
    jobs: &[RunJobRow],
    now: time::OffsetDateTime,
) -> crate::error::Result<Option<RunFailure>> {
    if jobs.iter().any(|job| !job_settled(job)) {
        return Ok(None);
    }
    let Some(job) = jobs
        .iter()
        .find(|job| job.conclusion.as_deref() == Some("failure"))
    else {
        return Ok(Some(RunFailure::Infrastructure {
            job: "-".to_owned(),
            step: None,
            html_url: String::new(),
        }));
    };
    if let Some(step) = job.steps.iter().find(|step| !row_completed(&step.status)) {
        let Some(completed_at) = job.completed_at else {
            return Err(stow_error!(
                "jobs page: settled job {:?} (status {:?}, conclusion {:?}) carries no completed_at",
                job.name,
                job.status,
                job.conclusion.as_deref().unwrap_or("<none>")
            ));
        };
        if now - completed_at < STEP_SETTLE_WINDOW + GITHUB_CLOCK_ALLOWANCE {
            return Ok(None);
        }
        return Ok(Some(RunFailure::Infrastructure {
            job: job.name.clone(),
            step: Some(step.name.clone()),
            html_url: job.html_url.clone(),
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
            html_url: job.html_url.clone(),
        }));
    };
    if VERDICT_STEPS.contains(&step.name.as_str()) {
        Ok(Some(RunFailure::Verdict {
            job: job.name.clone(),
            step: step.name.clone(),
            html_url: job.html_url.clone(),
        }))
    } else {
        Ok(Some(RunFailure::Infrastructure {
            job: job.name.clone(),
            step: Some(step.name.clone()),
            html_url: job.html_url.clone(),
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
    /// `build <crate> <version> (<target>)`.
    pub name: String,
    /// `queued`/`in_progress`/`completed`/`waiting`/`pending` as
    /// GitHub serves it — a run's `completed` arrives while its job
    /// rows are still settling, and a finished job's can lag its
    /// `conclusion` (stow#863), so classification reads both.
    pub status: String,
    /// `success`/`failure`/`skipped`/… — `None` while the job runs;
    /// only ever written on a finished job, so its presence settles
    /// the row whatever `status` says.
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

/// `GET actions/runs/{id}` — the run's coarse state.
///
/// `queued`/`in_progress`/`completed`/`waiting` as GitHub serves it;
/// `run_attempt` pins a jobs-page read to the attempt the scheduler
/// dispatched.
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

/// A run's Actions URL on the trusted repository.
///
/// The pointer a leg failure carries back to its run when the jobs
/// page holds no job to ask (a `startup_failure` run has no jobs).
/// GitHub's `html_url` for a run is exactly this shape.
#[must_use]
pub fn run_url(run_id: &str) -> String {
    format!(
        "https://github.com/{}/actions/runs/{run_id}",
        crate::trusted_builder::REPOSITORY
    )
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

#[cfg(test)]
mod tests {
    use super::{RunFailure, RunJobRow, RunStepRow, VERDICT_STEPS, classify_failure};
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
        let Ok(Some(RunFailure::Infrastructure { job, step, .. })) =
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
        let Ok(Some(RunFailure::Infrastructure { job, step, .. })) =
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

    /// stow#863: the observed shape on the failing job itself — a
    /// `completed` run's job row can read `in_progress` with its
    /// `conclusion` already written. A conclusion only ever lands on
    /// a finished job, so it settles the row whatever `status` says.
    #[test]
    fn a_concluded_job_is_settled_whatever_its_status_says() {
        let jobs = [job_row(
            "build",
            "in_progress",
            Some("failure"),
            Some(1_000_000),
            &[(
                "Run the untrusted build stage",
                "completed",
                Some("failure"),
            )],
        )];
        assert!(matches!(
            classify_failure(&jobs, at(1_000_100)),
            Ok(Some(RunFailure::Verdict { .. }))
        ));
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
        let last = "<https://api.github.com/x?page=1>; rel=\"prev\", <https://api.github.com/x>; rel=\"first\"";
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
