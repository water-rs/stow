//! The local CI server's run listing — `stow-build serve`'s `GET /tasks`
//! answer, read by `stow-admin preheat manual --dispatch-url` and the
//! `Preheat cost` lane (stow#773). One wire type, so the server and its
//! readers cannot drift.

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
    /// The run's name — `<rustc>-<task_id>` for a build
    /// ([`crate::records::run_title`]), the same shape `build-crate.yml`'s
    /// `run-name` stamps on the real API.
    pub display_title: String,
    /// `queued`, `in_progress`, or `completed` — the GitHub Actions
    /// `status` field's spelling.
    pub status: String,
    /// `success` or `failure` once `status` is `completed`; `null`
    /// before, exactly like the API.
    pub conclusion: Option<String>,
    /// Where a human would look — the failure list prints it.
    pub html_url: String,
    /// When the dispatch arrived, Unix milliseconds — the instant the
    /// scheduler released the task, which a harness orders against the
    /// slice reports that released its dependencies.
    pub dispatched_at_ms: u64,
    /// When the run reached `completed`, Unix milliseconds.
    pub completed_at_ms: Option<u64>,
    /// Why a failed run failed — the stage's own final error, so a
    /// harness can name the cause without reading the server log.
    pub error: Option<String>,
    /// Every `workflow_run` delivery attempt the edge refused, in order,
    /// including attempts a later retry recovered from: a delivery the
    /// edge answered with an error happened even when the run landed.
    pub delivery_errors: Vec<String>,
}
