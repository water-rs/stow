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
    /// The run's name — `<rustc>-b<batch_id>` for a build batch
    /// ([`crate::records::batch_run_title`]), the same shape
    /// `build-batch.yml`'s `run-name` stamps on the real API.
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
    /// A failure no single leg owns — the dispatch itself or a
    /// `workflow_run` delivery — so a harness can name the cause
    /// without reading the server log. It applies to every leg of the
    /// run; a leg's own build or publish error rides
    /// [`LocalCiLeg::error`] instead.
    pub error: Option<String>,
    /// Every `workflow_run` delivery attempt the edge refused, in order,
    /// including attempts a later retry recovered from: a delivery the
    /// edge answered with an error happened even when the run landed.
    pub delivery_errors: Vec<String>,
    /// A build run's matrix legs (stow#833) — one per task the batch
    /// carries, in batch order. A `resolve-request` run has none: it
    /// fans nothing out.
    pub legs: Vec<LocalCiLeg>,
}

/// One leg of a batched build run — the per-task row `GET /tasks`
/// folds to a task state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCiLeg {
    /// The leg's index into the batch's `tasks` —
    /// [`crate::api::BatchTask::leg`].
    pub leg: u32,
    /// The scheduler task id the leg builds —
    /// [`crate::api::BatchTask::task_id`].
    pub task_id: String,
    /// `queued`, `in_progress`, or `completed` — the GitHub Actions
    /// `status` field's spelling, per leg.
    pub status: String,
    /// `success`, `failure` or `cancelled` once `status` is
    /// `completed`; `null` before, exactly like the API.
    pub conclusion: Option<String>,
    /// That leg's build or publish error — `None` for a leg that
    /// succeeded or has not finished.
    pub error: Option<String>,
}

/// `POST /seeded-runs`: `build-batch.yml` runs that already exist
/// upstream when the harness starts.
///
/// These are the scheduler fixture's bound in-flight batches
/// (`crate::fixture::FixtureShape::in_flight_batch`), dispatched before
/// the store was seeded rather than through `/dispatch`. The server
/// records each as a finished run whose every
/// leg succeeded, so its run object and attempt-jobs page answer as
/// GitHub's would once the run completed; the caller delivers the
/// run's `workflow_run` completion and publishes each leg's records
/// artifact itself.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LocalCiSeededRuns {
    /// The runs to record, each under its own id.
    pub runs: Vec<LocalCiSeededRun>,
}

/// One run [`LocalCiSeededRuns`] records.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LocalCiSeededRun {
    /// The run id the batch is bound to — unique among every run the
    /// server holds or will allocate.
    pub workflow_run_id: u64,
    /// The batch's rustc — the run title's lead.
    pub rustc_version: crate::identity::WireRustcVersion,
    /// The batch the run carries — the run title's `b<batch_id>`.
    pub batch_id: crate::api::BatchId,
    /// Each leg's task id, in leg order.
    pub legs: Vec<String>,
}
