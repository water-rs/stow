//! The local CI server's `GET /tasks` run listing.
//!
//! `stow-build serve`'s answer, read by `stow-admin preheat manual
//! --dispatch-url` and the `Preheat cost` lane (stow#773). One wire
//! type, so the server and its readers cannot drift.

use serde::{Deserialize, Serialize};

/// `GET /tasks`: every run the server was dispatched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCiTasks {
    /// One row per dispatch, including repeated dispatches of a task.
    pub tasks: Vec<LocalCiRun>,
}

/// One dispatched run — the local stand-in for a GitHub Actions
/// workflow run, with the fields the API spells the same way.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCiRun {
    /// Numeric GitHub-compatible run identity, stable for this dispatch.
    pub workflow_run_id: u64,
    /// The run's name — `<rustc>-<task_id>` for a build run
    /// ([`crate::records::run_title`]), the same shape
    /// `build-crate.yml`'s `run-name` stamps on the real API.
    pub display_title: String,
    /// `queued`, `in_progress`, or `completed` — the GitHub Actions
    /// `status` field's spelling.
    pub status: String,
    /// `success` or `failure` once `status` is `completed`; `null`
    /// before, exactly like the API.
    pub conclusion: Option<String>,
    /// Where a human would look — the failure list prints it.
    pub html_url: String,
    /// The workflow file the run belongs to, as GitHub's run `path`
    /// spells it (`.github/workflows/<file>`) — what tells a build run
    /// from a resolve run.
    pub path: String,
    /// When the dispatch arrived, Unix milliseconds — the instant the
    /// scheduler released the task, which a harness orders against the
    /// slice reports that released its dependencies.
    pub dispatched_at_ms: u64,
    /// When the run reached `completed`, Unix milliseconds.
    pub completed_at_ms: Option<u64>,
    /// A failure the run's own jobs did not report — the dispatch
    /// itself or a `workflow_run` delivery — so a harness can name the
    /// cause without reading the server log.
    pub error: Option<String>,
    /// Every `workflow_run` delivery attempt the edge refused, in order,
    /// including attempts a later retry recovered from: a delivery the
    /// edge answered with an error happened even when the run landed.
    pub delivery_errors: Vec<String>,
    /// A build run's task — the scheduler task id the run builds. A
    /// `resolve-request` run has none: it fans nothing out.
    pub task_id: Option<String>,
}

/// `POST /seeded-runs`: `build-crate.yml` runs that exist upstream
/// without a dispatch through the server.
///
/// Two callers seed them. The traffic-cost harness seeds the scheduler
/// fixture's bound in-flight runs
/// (`crate::fixture::FixtureShape::in_flight_run`), each under the run
/// id the fixture already bound. The budget probe's run-resolution
/// drives seed the run a drive's claimed task ran as under an id the
/// server allocates, and bind the task to it. The server records each
/// run in the [`LocalCiSeededStatus`] it names, so its run object
/// answers as GitHub's would at that point, and it publishes the
/// records artifact under the run's tag before it records the run, as
/// the run's publish job would have. Nothing drives a seeded run
/// afterwards: a running one stays running, and the caller delivers
/// any `workflow_run` completion itself.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LocalCiSeededRuns {
    /// The runs to record.
    pub runs: Vec<LocalCiSeededRun>,
}

/// One run [`LocalCiSeededRuns`] records.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LocalCiSeededRun {
    /// The run's id. `Some` names a run bound before the server
    /// started, unique among every run the server holds or will
    /// allocate; `None` has the server allocate it, as GitHub assigns a
    /// dispatch's.
    pub workflow_run_id: Option<u64>,
    /// The run's rustc — the run title's lead and the records tag's
    /// namespace.
    pub rustc_version: crate::identity::WireRustcVersion,
    /// The task the run builds — the run title's `<task_id>` half.
    pub task_id: String,
    /// Where the run stands — GitHub's `status` and, once `completed`,
    /// its `conclusion`, both at the run's top level as the API spells
    /// them.
    #[serde(flatten)]
    pub status: LocalCiSeededStatus,
}

/// Where a [`LocalCiSeededRun`] stands — GitHub's `status`, with the
/// `conclusion` only a `completed` run carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LocalCiSeededStatus {
    /// The build job is running and the publish job has not started,
    /// so nothing is published and the run's `conclusion` is `null`.
    InProgress,
    /// The run finished at `conclusion`.
    Completed {
        /// How the run ended.
        conclusion: LocalCiSeededConclusion,
    },
}

/// The outcome of a completed [`LocalCiSeededRun`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LocalCiSeededConclusion {
    /// The build and publish jobs succeeded and the records artifact
    /// is published; the run concluded `success`.
    Success,
    /// The build job failed at its first verdict step and the publish
    /// job was skipped, so nothing published records; the run
    /// concluded `failure`.
    Failure,
}

/// `POST /seeded-runs`' answer: each seeded run's id, in request order,
/// so a caller that let the server allocate learns the id it binds.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LocalCiSeededRunIds {
    /// The run ids, one per requested run.
    pub runs: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use super::{LocalCiSeededConclusion, LocalCiSeededRun, LocalCiSeededStatus};

    /// A seeded run's state is spelled at the run's top level as GitHub
    /// spells a run object's — `status`, plus `conclusion` once
    /// `completed` — and reads back as the state it was written as.
    #[test]
    fn a_seeded_run_spells_its_state_as_a_github_run_does() {
        let task_id = format!("{:064x}", 5_u64);
        for (status, expected) in [
            (
                LocalCiSeededStatus::InProgress,
                serde_json::json!({ "status": "in_progress" }),
            ),
            (
                LocalCiSeededStatus::Completed {
                    conclusion: LocalCiSeededConclusion::Failure,
                },
                serde_json::json!({ "status": "completed", "conclusion": "failure" }),
            ),
        ] {
            let run = LocalCiSeededRun {
                workflow_run_id: None,
                rustc_version: crate::identity::WireRustcVersion::parse("1.86.0".to_owned())
                    .unwrap(),
                task_id: task_id.clone(),
                status,
            };
            let value = serde_json::to_value(&run).unwrap();
            for (key, spelled) in expected.as_object().unwrap() {
                assert_eq!(&value[key], spelled, "{key} of {value}");
            }
            if status == LocalCiSeededStatus::InProgress {
                assert!(value.get("conclusion").is_none(), "{value}");
            }
            let read: LocalCiSeededRun = serde_json::from_value(value).unwrap();
            assert_eq!(read.status, status);
        }
    }
}
