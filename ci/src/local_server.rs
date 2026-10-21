//! Dev-only local CI dispatch server.
//!
//! Activated via `stow-build serve`. Implements `POST /dispatch` so a
//! locally-running edge worker can dispatch `build-batch` runs (a
//! `BuildBatchPayload`) and `resolve-request` runs (a `RequestDispatch`)
//! for end-to-end tests without touching real GitHub Actions — the
//! GitHub-shaped run endpoints the edge's `LocalCiBuildRuns` drives on
//! the same loopback base (`GET/POST …/actions/runs/{id}` plus the
//! attempt-jobs listing and `…/cancel`), and `GET /tasks`, the
//! run-state list `stow-admin preheat manual` polls in its
//! `--dispatch-url` mode.
//!
//! A batch run mirrors the production shape exactly: one run id for the
//! batch, an event file carrying the dispatch input, and per leg a build
//! in one process, a publish stage that lands the leg's records artifact
//! in the mock registry, and `build #N`/`publish #N` job rows named as
//! GitHub names reusable-workflow matrix jobs. Completion reaches the
//! edge as one `workflow_run` webhook POST for the run — the same
//! `X-Hub-Signature-256` HMAC GitHub signs with — never a scheduler call.
//!
//! Uses skyzen + skyzen-hyper for routing so the same DSL is shared with the
//! edge worker and there is exactly one HTTP server framework in the
//! workspace. async-net provides a futures-compatible TCP listener so we
//! avoid the tokio-IO / futures-IO bridging dance.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_net::TcpListener;
use executor_core::tokio::TokioGlobal;
use futures_lite::stream;
use futures_util::StreamExt as _;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use skyzen::Server;
use skyzen::extract::Query;
use skyzen::routing::{CreateRouteNode, Params, Route, Router};
use skyzen::utils::{Json, State};
use skyzen::{Body, Response, StatusCode};
use stow_types::api::{BatchTask, BuildBatchPayload, RequestDispatch, TaskHash};
use stow_types::local_ci::{
    LocalCiLeg, LocalCiRun, LocalCiSeededConclusion, LocalCiSeededRun, LocalCiSeededRunIds,
    LocalCiSeededRuns,
};
use stow_types::runs::VERDICT_STEPS;
use tokio::sync::Semaphore;
use tokio::time::{Duration, sleep};
use zenwave::{Client, ResponseExt};

type HmacSha256 = Hmac<Sha256>;

/// Per-process state injected into every `/dispatch` invocation.
#[derive(Clone)]
pub struct LocalServerState {
    /// Edge URL prefix (no trailing slash) — the `workflow_run` webhook
    /// posts to `{edge_url}/api/v1/github/workflow-run`.
    pub edge_url: String,
    /// Shared secret the webhook signature is computed with — the
    /// `STOW_GITHUB_WEBHOOK_SECRET` binding's local value.
    pub webhook_secret: String,
    /// Filesystem path to the mock cosign private key.
    pub mock_private_key_path: String,
    /// Root directory the mock OCI registry serves out of.
    pub mock_registry_root: String,
    /// Every dispatched run's state, served by `GET /tasks`.
    pub runs: Arc<Mutex<BTreeMap<String, LocalCiRun>>>,
    /// Every batch run's job rows by run id — the rows GitHub's jobs
    /// API serves for the run.
    jobs: Arc<Mutex<BTreeMap<u64, Vec<RecordedJob>>>>,
    /// Run ids a `POST …/cancel` has landed — queued legs check it
    /// before starting and the run's conclusion reads it once the
    /// running legs settle.
    cancels: Arc<Mutex<BTreeSet<u64>>>,
    /// The local equivalent of GitHub assigning a fresh id to every
    /// workflow dispatch and every job.
    next_id: Arc<AtomicU64>,
    /// The runner pool. A dispatch is accepted at once, as GitHub queues
    /// it, but at most one build or publish per core executes: on Actions
    /// every job has a machine of its own, here they all share one with
    /// the edge under test, and an unbounded wave of builds starves it.
    runners: Arc<Semaphore>,
    /// The bound listen address, filled by `serve` — the `html_url` a
    /// mock run reports.
    pub listen: SocketAddr,
}

impl std::fmt::Debug for LocalServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalServerState")
            .field("edge_url", &self.edge_url)
            .field("mock_registry_root", &self.mock_registry_root)
            .field("listen", &self.listen)
            .finish_non_exhaustive()
    }
}

impl LocalServerState {
    /// Assemble the state `serve` runs with; `listen` is overwritten by
    /// the bound address once the socket opens.
    pub fn new(
        edge_url: String,
        webhook_secret: String,
        mock_private_key_path: String,
        mock_registry_root: String,
    ) -> Self {
        Self {
            edge_url,
            webhook_secret,
            mock_private_key_path,
            mock_registry_root,
            runs: Arc::new(Mutex::new(BTreeMap::new())),
            jobs: Arc::new(Mutex::new(BTreeMap::new())),
            cancels: Arc::new(Mutex::new(BTreeSet::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            runners: Arc::new(Semaphore::new(
                std::thread::available_parallelism()
                    .expect("read the machine's available parallelism")
                    .get(),
            )),
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        }
    }

    /// A fresh run or job id — GitHub assigns every dispatch and every
    /// job one, including a repeated dispatch of the same batch.
    fn allocate_id(&self) -> u64 {
        self.next_id
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .expect("local workflow id space exhausted")
    }

    /// Record a dispatched run under the id GitHub assigned it. The
    /// display title remains the workflow's stable batch/request
    /// run-name, so repeated dispatches retain separate records.
    fn mark_run(
        &self,
        workflow_run_id: u64,
        workflow_file: &str,
        display_title: &str,
        status: &'static str,
        conclusion: Option<&'static str>,
    ) {
        let now = unix_millis();
        let mut runs = self.runs.lock().expect("runs mutex poisoned");
        let entry = runs
            .entry(workflow_run_id.to_string())
            .or_insert_with(|| LocalCiRun {
                workflow_run_id,
                display_title: display_title.to_string(),
                status: status.to_owned(),
                conclusion: conclusion.map(str::to_owned),
                html_url: format!("http://{}/tasks/{workflow_run_id}", self.listen),
                path: format!(".github/workflows/{workflow_file}"),
                dispatched_at_ms: now,
                completed_at_ms: None,
                error: None,
                delivery_errors: Vec::new(),
                legs: Vec::new(),
            });
        status.clone_into(&mut entry.status);
        entry.conclusion = conclusion.map(str::to_owned);
        if status == "completed" {
            entry.completed_at_ms = Some(now);
        }
        drop(runs);
    }

    /// Record why a run failed.
    fn record_error(&self, workflow_run_id: u64, error: &str) {
        if let Some(run) = self
            .runs
            .lock()
            .expect("runs mutex poisoned")
            .get_mut(&workflow_run_id.to_string())
        {
            run.error = Some(error.to_owned());
        }
    }

    /// Whether a run record exists for `run_id` — the GitHub-shaped
    /// run endpoints' 404 test.
    fn run_exists(&self, run_id: u64) -> bool {
        self.runs
            .lock()
            .expect("runs mutex poisoned")
            .contains_key(&run_id.to_string())
    }

    /// Whether a `POST …/cancel` landed for `run_id`.
    fn cancel_requested(&self, run_id: u64) -> bool {
        self.cancels
            .lock()
            .expect("cancels mutex poisoned")
            .contains(&run_id)
    }

    /// Seed a batch run's legs as `queued` — GitHub queues the whole
    /// matrix at dispatch; `run_leg` flips each leg to `in_progress`
    /// then `completed` as its jobs settle.
    fn seed_legs(&self, workflow_run_id: u64, batch: &BuildBatchPayload) {
        if let Some(run) = self
            .runs
            .lock()
            .expect("runs mutex poisoned")
            .get_mut(&workflow_run_id.to_string())
        {
            run.legs = batch
                .tasks
                .iter()
                .map(|task| LocalCiLeg {
                    leg: task.leg,
                    task_id: task.task_id.clone(),
                    status: "queued".to_owned(),
                    conclusion: None,
                    error: None,
                })
                .collect();
        }
    }

    /// Flip leg `leg` of run `run_id` to `status`/`conclusion` — the
    /// per-leg row `GET /tasks` serves. A failure settles with its
    /// `error` recorded on the leg itself, so a reader never parses
    /// which leg failed back out of the run's joined summary.
    fn set_leg(
        &self,
        run_id: u64,
        leg: u32,
        status: &'static str,
        conclusion: Option<&'static str>,
        error: Option<&str>,
    ) {
        if let Some(entry) = self
            .runs
            .lock()
            .expect("runs mutex poisoned")
            .get_mut(&run_id.to_string())
            .and_then(|run| run.legs.iter_mut().find(|entry| entry.leg == leg))
        {
            status.clone_into(&mut entry.status);
            entry.conclusion = conclusion.map(str::to_owned);
            if let Some(error) = error {
                entry.error = Some(error.to_owned());
            }
        }
    }

    /// Record one refused `workflow_run` delivery attempt.
    fn record_delivery_error(&self, workflow_run_id: u64, error: &str) {
        if let Some(run) = self
            .runs
            .lock()
            .expect("runs mutex poisoned")
            .get_mut(&workflow_run_id.to_string())
        {
            run.delivery_errors.push(error.to_owned());
        }
    }

    /// Open a job row of run `run_id` as `in_progress`, its first step
    /// running and the rest pending — the shape GitHub serves while a
    /// job runs. Returns the job's id.
    fn begin_job(&self, run_id: u64, name: String, steps: &[&str]) -> u64 {
        let job_id = self.allocate_id();
        let job = RecordedJob {
            id: job_id,
            name,
            status: "in_progress",
            conclusion: None,
            started_at: Some(time::OffsetDateTime::now_utc()),
            completed_at: None,
            run_attempt: RUN_ATTEMPT,
            html_url: format!("http://{}/tasks/{run_id}/job/{job_id}", self.listen),
            steps: steps
                .iter()
                .enumerate()
                .map(|(index, name)| RecordedStep {
                    name: (*name).to_owned(),
                    status: if index == 0 { "in_progress" } else { "pending" },
                    conclusion: None,
                })
                .collect(),
        };
        self.jobs
            .lock()
            .expect("jobs mutex poisoned")
            .entry(run_id)
            .or_default()
            .push(job);
        job_id
    }

    /// Settle the job `job_id` of run `run_id`: `conclusion` for the job
    /// and one conclusion per step, in step order.
    fn finish_job(
        &self,
        run_id: u64,
        job_id: u64,
        conclusion: &'static str,
        step_conclusions: &[&'static str],
    ) {
        let mut jobs = self.jobs.lock().expect("jobs mutex poisoned");
        let job = jobs
            .get_mut(&run_id)
            .and_then(|jobs| jobs.iter_mut().find(|job| job.id == job_id))
            .expect("a finished job was begun on its run");
        assert_eq!(
            job.steps.len(),
            step_conclusions.len(),
            "job {:?} settles every step",
            job.name
        );
        job.status = "completed";
        job.conclusion = Some(conclusion);
        job.completed_at = Some(time::OffsetDateTime::now_utc());
        for (step, conclusion) in job.steps.iter_mut().zip(step_conclusions) {
            step.status = "completed";
            step.conclusion = Some(conclusion);
        }
        drop(jobs);
    }

    /// Record a job that never ran — a completed row with no steps,
    /// the conclusion naming why: `skipped` when its `if:` was false,
    /// `cancelled` when the run's cancel beat a runner to it.
    fn close_unstarted_job(&self, run_id: u64, name: String, conclusion: &'static str) {
        let job_id = self.allocate_id();
        let now = time::OffsetDateTime::now_utc();
        self.jobs
            .lock()
            .expect("jobs mutex poisoned")
            .entry(run_id)
            .or_default()
            .push(RecordedJob {
                id: job_id,
                name,
                status: "completed",
                conclusion: Some(conclusion),
                started_at: Some(now),
                completed_at: Some(now),
                run_attempt: RUN_ATTEMPT,
                html_url: format!("http://{}/tasks/{run_id}/job/{job_id}", self.listen),
                steps: Vec::new(),
            });
    }

    /// Record a job that never ran because its `if:` was false — a
    /// completed `skipped` row with no steps.
    fn skip_job(&self, run_id: u64, name: String) {
        self.close_unstarted_job(run_id, name, "skipped");
    }

    /// The id each of `seeded`'s runs is recorded under, in request
    /// order. A named id must sit above every id the server has
    /// allocated, and the allocator moves past the highest, so no later
    /// dispatch or job can take one: GitHub never hands out a run id
    /// twice. An unnamed run takes the allocator's next id, as a
    /// dispatch does. Refused before anything is assigned: an empty
    /// request, a run with no leg, or a named id that repeats.
    fn seeded_run_ids(&self, seeded: &LocalCiSeededRuns) -> Result<Vec<u64>, String> {
        if seeded.runs.is_empty() {
            return Err("no runs to seed".to_owned());
        }
        if let Some(run) = seeded.runs.iter().find(|run| run.legs.is_empty()) {
            return Err(format!("run of batch {} seeds no leg", run.batch_id));
        }
        let mut named: Vec<u64> = seeded
            .runs
            .iter()
            .filter_map(|run| run.workflow_run_id)
            .collect();
        named.sort_unstable();
        if let Some([twice, _]) = named.array_windows().find(|[a, b]| a == b) {
            return Err(format!("run id {twice} is seeded twice"));
        }
        if let (Some(&lowest), Some(&highest)) = (named.first(), named.last()) {
            let next = highest
                .checked_add(1)
                .ok_or_else(|| format!("run id {highest} leaves no id to allocate after it"))?;
            let previous = self.next_id.fetch_max(next, Ordering::Relaxed);
            if previous > lowest {
                return Err(format!(
                    "run id {lowest} is not above the ids this server already allocated \
                     (next was {previous})"
                ));
            }
        }
        Ok(seeded
            .runs
            .iter()
            .map(|run| run.workflow_run_id.unwrap_or_else(|| self.allocate_id()))
            .collect())
    }

    /// Publish every succeeded leg's records artifact for `seeded`, each
    /// run under its id in `ids`, before any run is recorded — a reader
    /// never sees a finished success whose records are missing. The
    /// artifact carries the empty set, as a stubbed dispatched leg's
    /// does. The pushes run concurrently, at most one per core, the
    /// bound the runner pool holds dispatched legs to. `exe` is the
    /// `stow-build` binary the mock registry binary sits beside.
    async fn publish_seeded_records(
        &self,
        seeded: &LocalCiSeededRuns,
        ids: &[u64],
        exe: &Path,
    ) -> stow_types::error::Result<()> {
        let dir = tempfile::tempdir()?;
        let records_path = dir.path().join("records.json");
        async_fs::write(&records_path, "[]").await?;
        let pushes: Vec<_> = seeded
            .runs
            .iter()
            .zip(ids)
            .filter(|(run, _)| run.conclusion == LocalCiSeededConclusion::Success)
            .flat_map(|(run, &run_id)| run.legs.iter().map(move |task_id| (run, run_id, task_id)))
            .map(|(run, run_id, task_id)| {
                push_records(
                    self,
                    task_id,
                    run.rustc_version.as_str(),
                    run_id,
                    &records_path,
                    exe,
                )
            })
            .collect();
        let bound = std::thread::available_parallelism()?.get();
        let results: Vec<stow_types::error::Result<()>> = futures_util::stream::iter(pushes)
            .buffer_unordered(bound)
            .collect()
            .await;
        results.into_iter().collect()
    }

    /// One seeded run under `run_id`: its run record with every leg
    /// `completed` at the run's conclusion, and per leg the `build` and
    /// `publish` job rows such a leg leaves — the same rows [`run_leg`]
    /// writes for a leg that succeeded, or that failed its build.
    fn record_seeded_run(&self, seeded: &LocalCiSeededRun, run_id: u64) {
        let now = unix_millis();
        let conclusion = match seeded.conclusion {
            LocalCiSeededConclusion::Success => "success",
            LocalCiSeededConclusion::Failure => "failure",
        };
        let legs = (0..)
            .zip(&seeded.legs)
            .map(|(leg, task_id)| LocalCiLeg {
                leg,
                task_id: task_id.clone(),
                status: "completed".to_owned(),
                conclusion: Some(conclusion.to_owned()),
                error: (seeded.conclusion == LocalCiSeededConclusion::Failure)
                    .then(|| format!("leg {leg} build: seeded as failed")),
            })
            .collect::<Vec<_>>();
        self.runs.lock().expect("runs mutex poisoned").insert(
            run_id.to_string(),
            LocalCiRun {
                workflow_run_id: run_id,
                display_title: stow_types::records::batch_run_title(
                    seeded.rustc_version.as_str(),
                    &seeded.batch_id,
                ),
                status: "completed".to_owned(),
                conclusion: Some(conclusion.to_owned()),
                html_url: format!("http://{}/tasks/{run_id}", self.listen),
                path: format!(
                    ".github/workflows/{}",
                    stow_types::trusted_builder::BATCH_WORKFLOW_FILE
                ),
                dispatched_at_ms: now,
                completed_at_ms: Some(now),
                error: None,
                delivery_errors: Vec::new(),
                legs,
            },
        );
        for (leg, task_id) in (0..).zip(&seeded.legs) {
            let hash = TaskHash::of(task_id);
            let build = self.begin_job(
                run_id,
                leg_build_job_name(leg, task_id, &hash),
                BUILD_JOB_STEPS,
            );
            match seeded.conclusion {
                LocalCiSeededConclusion::Success => {
                    self.finish_job(run_id, build, "success", &["success", "success"]);
                    let publish =
                        self.begin_job(run_id, leg_publish_job_name(leg, &hash), PUBLISH_JOB_STEPS);
                    self.finish_job(run_id, publish, "success", &["success"]);
                }
                LocalCiSeededConclusion::Failure => {
                    self.finish_job(run_id, build, "failure", &["failure", "success"]);
                    self.skip_job(run_id, leg_publish_job_name(leg, &hash));
                }
            }
        }
    }
}

/// Every mock run is a fresh dispatch, so attempt 1 — the attempt the
/// records push and the `workflow_run` webhook both name.
const RUN_ATTEMPT: u32 = 1;

/// The `build` job's step rows: the verdict steps that run the crate.
const BUILD_JOB_STEPS: &[&str] = &[VERDICT_STEPS[0], VERDICT_STEPS[1]];
/// The `publish` job's step rows: the trusted stage.
const PUBLISH_JOB_STEPS: &[&str] = &[VERDICT_STEPS[2]];

/// One job row of a batch run, in the shape of GitHub's job object — the
/// fields `stow_types::runs::RunJobRow` reads.
#[derive(Debug, Clone, serde::Serialize)]
struct RecordedJob {
    id: u64,
    name: String,
    status: &'static str,
    conclusion: Option<&'static str>,
    #[serde(with = "time::serde::rfc3339::option")]
    started_at: Option<time::OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    completed_at: Option<time::OffsetDateTime>,
    run_attempt: u32,
    html_url: String,
    steps: Vec<RecordedStep>,
}

/// One step row of a [`RecordedJob`].
#[derive(Debug, Clone, serde::Serialize)]
struct RecordedStep {
    name: String,
    status: &'static str,
    conclusion: Option<&'static str>,
}

/// The `build` job's name as GitHub names a reusable-workflow matrix
/// job: `"<caller job> / <called job>"`, the caller being
/// `build-batch.yml`'s `leg ${{ matrix.task.i }}` and the called job
/// `build-crate.yml`'s `build`.
fn build_job_name(leg: &BatchTask) -> String {
    leg_build_job_name(
        leg.leg,
        &format!("{} {} ({})", leg.crate_name, leg.version, leg.target),
        &leg.task_hash,
    )
}

/// The `publish` job's name — see [`build_job_name`].
fn publish_job_name(leg: &BatchTask) -> String {
    leg_publish_job_name(leg.leg, &leg.task_hash)
}

/// Leg `i`'s `build` job name over any label — `"leg <i> / build #<i>
/// <label> <hash>"`. A dispatched leg's label is its crate, version and
/// target ([`build_job_name`]); a seeded leg carries only its task id.
fn leg_build_job_name(i: u32, label: &str, hash: &TaskHash) -> String {
    format!("leg {i} / build #{i} {label} {hash}")
}

/// Leg `i`'s `publish` job name — `"leg <i> / publish #<i> <hash>"`.
fn leg_publish_job_name(i: u32, hash: &TaskHash) -> String {
    format!("leg {i} / publish #{i} {hash}")
}

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
struct RepositoryDispatchEvent {
    /// The scheduler's `trigger_workflow` discriminator — `build-batch`
    /// or `resolve-request`.
    event_type: String,
    /// The event's payload: a [`BuildBatchPayload`] for `build-batch`,
    /// a `stow_types::api::RequestDispatch` for `resolve-request`.
    client_payload: serde_json::Value,
}

#[derive(Debug, serde::Serialize)]
struct DispatchResponse {
    workflow_run_id: u64,
    run_url: String,
    html_url: String,
}

/// Bind and serve the dev dispatch endpoint.
pub async fn serve(
    listen: SocketAddr,
    mut state: LocalServerState,
) -> stow_types::error::Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|error| stow_types::stow_error!("bind local ci server {}: {error}", listen))?;
    state.listen = listener
        .local_addr()
        .map_err(|error| stow_types::stow_error!("read bound address: {error}"))?;
    let router = build_router(state);

    tracing::info!(%listen, "local CI server listening");
    let connections = Box::pin(stream::unfold(listener, |listener| async move {
        let result = listener.accept().await;
        Some((result.map(|(stream, _addr)| stream), listener))
    }));

    skyzen::hyper::Hyper
        .serve(
            TokioGlobal,
            |error| tracing::error!(%error, "local CI server connection error"),
            connections,
            router,
        )
        .await;
    Ok(())
}

fn build_router(state: LocalServerState) -> Router {
    Route::new((
        "/dispatch".post(dispatch),
        "/seeded-runs".post(seed_runs),
        "/tasks".at(list_tasks),
        // The GitHub Actions control plane the edge's
        // `LocalCiBuildRuns` drives on the loopback base — the same
        // paths and shapes api.github.com serves, for run ids this
        // mock allocated.
        "/repos/{owner}/{repo}/actions/runs/{id}".at(get_run),
        "/repos/{owner}/{repo}/actions/runs/{id}/attempts/{attempt}/jobs".at(get_attempt_jobs),
        "/repos/{owner}/{repo}/actions/runs/{id}/cancel".post(cancel_run),
    ))
    .with(State(state))
    .build()
}

/// `GET /tasks` — the run list `stow-admin preheat manual` polls when it
/// drives the local runner, answering the same shape the GitHub runs API
/// does (`status`/`conclusion`/`display_title` semantics), each build
/// run's legs folded in.
async fn list_tasks(State(state): State<LocalServerState>) -> Response {
    let tasks = state
        .runs
        .lock()
        .expect("runs mutex poisoned")
        .values()
        .cloned()
        .collect();
    json_response(
        &stow_types::local_ci::LocalCiTasks { tasks },
        StatusCode::OK,
    )
}

/// GitHub's not-found envelope — `{"message": "Not Found"}` at 404, the
/// answer an unknown run id gets on every run endpoint.
fn not_found() -> Response {
    json_response(
        &serde_json::json!({ "message": "Not Found" }),
        StatusCode::NOT_FOUND,
    )
}

/// The `{id}` path parameter the run endpoints share — a missing or
/// non-numeric id is a 404, like a run GitHub never heard of.
fn run_id_param(params: &Params) -> Option<u64> {
    params.get("id").ok()?.parse().ok()
}

/// The workflow's `name:` as GitHub serves it on a run object — the
/// file stem of the run's `path`.
fn workflow_name(path: &str) -> &str {
    let file = path.rsplit('/').next().unwrap_or(path);
    file.strip_suffix(".yml").unwrap_or(file)
}

/// `GET /repos/{o}/{r}/actions/runs/{id}` — the run record in GitHub's
/// shape: the `status`/`conclusion`/`run_attempt`/`html_url` the
/// edge's lease check decodes, plus the name and title a reader
/// expects of a real run object.
async fn get_run(State(state): State<LocalServerState>, params: Params) -> Response {
    let Some(run_id) = run_id_param(&params) else {
        return not_found();
    };
    run_response(&state, run_id)
}

/// `GET …/runs/{id}`'s body for a run the mock holds — 404 otherwise.
fn run_response(state: &LocalServerState, run_id: u64) -> Response {
    let Some(run) = state
        .runs
        .lock()
        .expect("runs mutex poisoned")
        .get(&run_id.to_string())
        .cloned()
    else {
        return not_found();
    };
    json_response(
        &serde_json::json!({
            "id": run.workflow_run_id,
            "name": workflow_name(&run.path),
            "display_title": run.display_title,
            "status": run.status,
            "conclusion": run.conclusion,
            "run_attempt": RUN_ATTEMPT,
            "html_url": run.html_url,
            "path": run.path,
            "event": "workflow_dispatch",
            "head_branch": stow_types::trusted_builder::BRANCH,
        }),
        StatusCode::OK,
    )
}

/// `per_page`/`page` of the attempt-jobs listing — GitHub defaults a
/// jobs page to 30 rows.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
struct JobsQuery {
    /// Rows per page — GitHub's default 30, capped at 100.
    per_page: Option<u32>,
    /// 1-based page index — GitHub's default 1.
    page: Option<u32>,
}

/// `GET …/runs/{id}/attempts/{n}/jobs` — the run's recorded job rows
/// in GitHub's `{"total_count", "jobs"}` envelope, paged at the
/// request's `per_page` (default 30) with the `Link` header GitHub
/// emits while a page follows, so the edge's pager walks real pages.
async fn get_attempt_jobs(
    State(state): State<LocalServerState>,
    params: Params,
    Query(query): Query<JobsQuery>,
) -> Response {
    let Some(run_id) = run_id_param(&params) else {
        return not_found();
    };
    let Some(attempt) = params
        .get("attempt")
        .ok()
        .and_then(|attempt| attempt.parse::<u32>().ok())
    else {
        return not_found();
    };
    attempt_jobs_response(&state, run_id, attempt, &query)
}

/// `GET …/attempts/{n}/jobs`'s page — 404 on a run the mock does not
/// hold or an attempt it never ran (every mock run is attempt 1).
fn attempt_jobs_response(
    state: &LocalServerState,
    run_id: u64,
    attempt: u32,
    query: &JobsQuery,
) -> Response {
    if attempt != RUN_ATTEMPT || !state.run_exists(run_id) {
        return not_found();
    }
    let jobs = state
        .jobs
        .lock()
        .expect("jobs mutex poisoned")
        .get(&run_id)
        .cloned()
        .unwrap_or_default();
    attempt_jobs_page(state, run_id, attempt, &jobs, query)
}

/// One page of a run's attempt jobs: `jobs` sliced at `query`'s
/// `page`/`per_page`, plus the GitHub `Link` header — `next`/`last`
/// while a page follows, `first`/`prev` once off the first page —
/// whose URLs stay on this server's own origin so the edge's scoped
/// pager follows them.
fn attempt_jobs_page(
    state: &LocalServerState,
    run_id: u64,
    attempt: u32,
    jobs: &[RecordedJob],
    query: &JobsQuery,
) -> Response {
    let per_page = usize::try_from(query.per_page.unwrap_or(30).clamp(1, 100))
        .expect("a clamped page size fits usize");
    let page = usize::try_from(query.page.unwrap_or(1).max(1)).expect("a nonzero page fits usize");
    let start = (page - 1).saturating_mul(per_page);
    let mut response = json_response(
        &serde_json::json!({
            "total_count": jobs.len(),
            "jobs": jobs.iter().skip(start).take(per_page).collect::<Vec<_>>(),
        }),
        StatusCode::OK,
    );
    let page_url = |page: usize| {
        format!(
            "http://{}/repos/{}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page={per_page}&page={page}",
            state.listen,
            stow_types::trusted_builder::REPOSITORY,
        )
    };
    let mut links = Vec::new();
    if start + per_page < jobs.len() {
        links.push(format!("<{}>; rel=\"next\"", page_url(page + 1)));
        links.push(format!(
            "<{}>; rel=\"last\"",
            page_url(jobs.len().div_ceil(per_page))
        ));
    }
    if page > 1 {
        links.push(format!("<{}>; rel=\"first\"", page_url(1)));
        links.push(format!("<{}>; rel=\"prev\"", page_url(page - 1)));
    }
    if !links.is_empty() {
        response.headers_mut().insert(
            "link",
            skyzen::header::HeaderValue::from_str(&links.join(", "))
                .expect("link header values are visible ASCII"),
        );
    }
    response
}

/// `POST …/runs/{id}/cancel` — GitHub's 202. Legs still queued stop
/// where they are; running legs settle, then `drive_batch` reports the
/// run `completed`/`cancelled` through the usual `workflow_run`
/// webhook.
async fn cancel_run(State(state): State<LocalServerState>, params: Params) -> Response {
    let Some(run_id) = run_id_param(&params) else {
        return not_found();
    };
    cancel_response(&state, run_id)
}

/// `POST …/cancel`'s answer: record the run's cancel when the mock
/// holds it — 202 as GitHub answers — 404 when it does not.
fn cancel_response(state: &LocalServerState, run_id: u64) -> Response {
    let mut response = Response::new(Body::from(Vec::new()));
    *response.status_mut() = if state.run_exists(run_id) {
        state
            .cancels
            .lock()
            .expect("cancels mutex poisoned")
            .insert(run_id);
        StatusCode::ACCEPTED
    } else {
        StatusCode::NOT_FOUND
    };
    response
}

/// `POST /seeded-runs` — record runs that exist upstream without a
/// dispatch through this server ([`LocalCiSeededRuns`]): 201 with each
/// run's id ([`LocalCiSeededRunIds`]) once every succeeded leg's records
/// artifact is published and every run is recorded; 409 when a named id
/// collides with one this server allocated, the request names a run
/// twice or a run with no leg; 500 when a records push fails.
async fn seed_runs(
    State(state): State<LocalServerState>,
    Json(seeded): Json<LocalCiSeededRuns>,
) -> Response {
    let ids = match state.seeded_run_ids(&seeded) {
        Ok(ids) => ids,
        Err(error) => return json_response(&bad_request(&error), StatusCode::CONFLICT),
    };
    let published = match std::env::current_exe() {
        Ok(exe) => state.publish_seeded_records(&seeded, &ids, &exe).await,
        Err(error) => Err(error.into()),
    };
    if let Err(error) = published {
        return json_response(
            &bad_request(&format!("publish seeded records: {error}")),
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }
    for (run, &run_id) in seeded.runs.iter().zip(&ids) {
        state.record_seeded_run(run, run_id);
    }
    json_response(&LocalCiSeededRunIds { runs: ids }, StatusCode::CREATED)
}

/// `POST /dispatch` — the scheduler's one local fan-out: `build-batch`
/// events run the full simulated batch, `resolve-request` events are
/// the request lane's resolve-job dispatch (stow#428).
async fn dispatch(
    State(state): State<LocalServerState>,
    Json(event): Json<RepositoryDispatchEvent>,
) -> Response {
    match event.event_type.as_str() {
        "build-batch" => match serde_json::from_value::<BuildBatchPayload>(event.client_payload) {
            Ok(batch) => dispatch_batch(state, batch),
            Err(error) => json_response(
                &bad_request(&format!("build-batch payload: {error}")),
                StatusCode::BAD_REQUEST,
            ),
        },
        "resolve-request" => {
            match serde_json::from_value::<RequestDispatch>(event.client_payload) {
                Ok(dispatch) => dispatch_resolve(state, dispatch),
                Err(error) => json_response(
                    &bad_request(&format!("resolve-request payload: {error}")),
                    StatusCode::BAD_REQUEST,
                ),
            }
        }
        other => json_response(
            &bad_request(&format!("unknown event_type `{other}`")),
            StatusCode::BAD_REQUEST,
        ),
    }
}

/// Now as Unix milliseconds — the run record's clock.
fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn bad_request(error: &str) -> serde_json::Value {
    serde_json::json!({ "error": error })
}

/// A `build-batch` dispatch: one run id for the whole batch, every leg
/// built and published in the background, and one `workflow_run`
/// webhook when the last leg settles.
fn dispatch_batch(state: LocalServerState, batch: BuildBatchPayload) -> Response {
    let workflow_run_id = state.allocate_id();
    let run = batch_workflow_run(&state, &batch, workflow_run_id, "in_progress", None, None);
    state.mark_run(
        workflow_run_id,
        run.workflow_file,
        &run.display_title,
        "in_progress",
        None,
    );
    state.seed_legs(workflow_run_id, &batch);
    let response = dispatch_response(&run);
    tokio::spawn(drive_batch(state, batch, workflow_run_id));
    json_response(&response, StatusCode::ACCEPTED)
}

/// Run every leg of a dispatched batch, then report the run: the
/// `completed` webhook is delivered before the run reads `completed`
/// in `GET /tasks`, so a caller that sees no batch run in progress
/// knows no callback is still in flight (scripts/traffic-cost.sh).
async fn drive_batch(state: LocalServerState, batch: BuildBatchPayload, workflow_run_id: u64) {
    // `failure` is the run's conclusion cause; `run_error` is only the
    // failure no leg owns — each failed leg carries its own error on
    // its `LocalCiLeg`, so the joined summary never lands on the run.
    let (failure, run_error) = match run_legs(&state, &batch, workflow_run_id).await {
        Ok((root, failures)) => {
            let failure = failures.first().map(|first| {
                format!(
                    "{} of {} legs failed; {first}",
                    failures.len(),
                    batch.tasks.len()
                )
            });
            if failure.is_none() {
                // The runner a dispatch stands in for is ephemeral: a
                // landed run leaves nothing behind, so a whole preheat
                // wave does not keep every crate's unpacked workspace on
                // disk. A failed run keeps its tree.
                if let Err(error) = async_fs::remove_dir_all(&root).await {
                    tracing::error!(%error, root = %root.display(), "remove the landed run's directory");
                }
            }
            (failure, None)
        }
        Err(error) => {
            let error = format!("local CI dispatch failed: {error}");
            (Some(error.clone()), Some(error))
        }
    };
    // A cancel the run collected while its legs ran outranks their
    // own conclusions, exactly as GitHub reports `cancelled`.
    let conclusion = if state.cancel_requested(workflow_run_id) {
        "cancelled"
    } else if failure.is_some() {
        "failure"
    } else {
        "success"
    };
    if let Some(error) = &failure {
        tracing::error!(batch_id = %batch.batch_id, %error, "local CI batch run failed");
    }
    if let Some(error) = &run_error {
        state.record_error(workflow_run_id, error);
    }
    let report = batch_workflow_run(
        &state,
        &batch,
        workflow_run_id,
        "completed",
        Some(conclusion),
        failure,
    );
    let reported = post_workflow_run(&state, &report).await;
    state.mark_run(
        workflow_run_id,
        report.workflow_file,
        &report.display_title,
        "completed",
        Some(conclusion),
    );
    if let Err(error) = reported {
        tracing::error!(
            batch_id = %batch.batch_id,
            %error,
            "failed to report local CI batch run via webhook"
        );
        state.record_error(workflow_run_id, &format!("workflow_run webhook: {error}"));
    }
}

/// A `resolve-request` dispatch (stow#428): the stub absorbs the hop
/// the admit pass pays, records the run and reports `in_progress`
/// through the same signed `workflow_run` webhook a real Actions job
/// emits when its job starts. The resolve itself — `stow-admin request
/// resolve`, its outcome report, run completion — is not simulated:
/// the record the admit pass wrote stays `resolving` here until the
/// operator drives the resolve for real.
fn dispatch_resolve(state: LocalServerState, dispatch: RequestDispatch) -> Response {
    let workflow_run_id = state.allocate_id();
    let display_title =
        stow_types::records::resolve_run_title(dispatch.attempt, &dispatch.request_id);
    let run_key = resolve_run_key(&dispatch);
    state.mark_run(
        workflow_run_id,
        stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE,
        &display_title,
        "in_progress",
        None,
    );
    let report = WorkflowRunReport {
        workflow_run_id,
        run_key,
        workflow_file: stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE,
        display_title,
        action: "in_progress",
        conclusion: None,
        html_url: format!("http://{}/tasks/{workflow_run_id}", state.listen),
        error: None,
    };
    let response = dispatch_response(&report);
    tokio::spawn(async move {
        if let Err(error) = post_workflow_run(&state, &report).await {
            tracing::error!(
                request_id = %dispatch.request_id,
                %error,
                "failed to report resolve run in_progress via webhook"
            );
        }
    });
    json_response(&response, StatusCode::ACCEPTED)
}

fn dispatch_response(run: &WorkflowRunReport) -> DispatchResponse {
    let workflow_run_id = run.workflow_run_id;
    let url = run.html_url.clone();
    DispatchResponse {
        workflow_run_id,
        run_url: url.clone(),
        html_url: url,
    }
}

fn json_response(payload: &impl serde::Serialize, status: StatusCode) -> Response {
    let body = serde_json::to_vec(payload).expect("response always serializes");
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        "content-type",
        skyzen::header::HeaderValue::from_static("application/json"),
    );
    response
}

/// Whether `STOW_LOCAL_CI_STUB` short-circuits the build and publish
/// stages: the dispatch POST — the hop the alarm pass pays per claimed
/// batch — is the piece the budget probe and the launch load run
/// measure, and a real cargo build per leg is orders of magnitude
/// heavier than either can afford. A stubbed run still completes
/// through the same signed `workflow_run` webhook, so the completion
/// lands and `GET /tasks` reports a finished run; only the
/// post-dispatch build work is stubbed. Each leg's records artifact is
/// still pushed (empty) first, because the webhook verifies every
/// succeeded leg's records artifact before applying a success — the
/// same object production writes for an artifact-less task.
fn stubbed() -> bool {
    std::env::var_os("STOW_LOCAL_CI_STUB").is_some()
}

/// One dispatched batch run: what every leg of it shares.
struct BatchRun {
    state: LocalServerState,
    batch: BuildBatchPayload,
    /// The run id allocated for the whole batch.
    workflow_run_id: u64,
    /// Per-run working directory under `.tmp/local-ci-dispatch`.
    root: PathBuf,
    /// The `workflow_dispatch` event file the stages read their leg
    /// from (`GITHUB_EVENT_PATH`).
    event_path: PathBuf,
    /// The matrix's `max-parallel`: a leg holds a slot from its build
    /// to the end of its publish.
    slots: Semaphore,
    /// Skip the build and publish work, pushing only each leg's empty
    /// records artifact ([`stubbed`]).
    stub: bool,
    /// The `stow-build` binary — the build stage's executable and the
    /// directory the mock registry binary sits in.
    exe: PathBuf,
}

/// Filesystem layout of one leg's working directory: the workspace the
/// build stage unpacks into, the output directory it writes to, and the
/// files the two stages exchange.
struct LegLayout {
    /// Per-leg working directory under the run's.
    root: PathBuf,
    /// `stow-build build --output-dir`: plan and content-addressed blobs.
    output_dir: PathBuf,
    /// Upload plan the build stage writes and `populate` consumes.
    upload_plan_path: PathBuf,
    /// Artifact records `populate` writes for the records-artifact step.
    records_path: PathBuf,
    /// The build stage's stderr — its final error names why it failed.
    build_log_path: PathBuf,
}

impl LegLayout {
    async fn create(run_root: &Path, leg: usize) -> stow_types::error::Result<Self> {
        let root = run_root.join(format!("leg-{leg}"));
        async_fs::create_dir_all(&root).await?;
        let output_dir = root.join("output");
        Ok(Self {
            upload_plan_path: output_dir.join("upload-plan.json"),
            records_path: root.join("records.json"),
            build_log_path: root.join("build-stage.log"),
            root,
            output_dir,
        })
    }
}

/// Create the run's directory under `.tmp/local-ci-dispatch`. The
/// directory names the run, so a repeated dispatch of one batch gets its
/// own tree and a failed run's `build-stage.log`s survive for diagnosis
/// (stow#773).
async fn create_run_root(
    batch: &BuildBatchPayload,
    workflow_run_id: u64,
) -> stow_types::error::Result<PathBuf> {
    let root = std::env::current_dir()?
        .join(".tmp")
        .join("local-ci-dispatch")
        .join(format!("{}-{workflow_run_id}", batch.batch_id));
    async_fs::create_dir_all(&root).await?;
    Ok(root)
}

/// Run all of a batch's legs, at most `parallelism` at once, and return
/// the run's directory with each failed leg's error in leg order.
async fn run_legs(
    state: &LocalServerState,
    batch: &BuildBatchPayload,
    workflow_run_id: u64,
) -> stow_types::error::Result<(PathBuf, Vec<String>)> {
    let parallelism = usize::try_from(batch.parallelism)?;
    if parallelism == 0 {
        return Err(stow_types::stow_error!(
            "batch {} has parallelism 0 — no leg could ever run",
            batch.batch_id
        ));
    }
    let root = create_run_root(batch, workflow_run_id).await?;
    let event_path = root.join("event.json");
    // The event file GitHub writes for a `workflow_dispatch`: the
    // batch rides its `inputs.batch` as a JSON-encoded string.
    let event = serde_json::json!({ "inputs": { "batch": batch.encode_dispatch_batch()? } });
    async_fs::write(&event_path, serde_json::to_vec(&event)?).await?;
    let run = Arc::new(BatchRun {
        state: state.clone(),
        batch: batch.clone(),
        workflow_run_id,
        root: root.clone(),
        event_path,
        slots: Semaphore::new(parallelism),
        stub: stubbed(),
        exe: std::env::current_exe()?,
    });
    // Every leg is queued at once, as GitHub queues a matrix; the slots
    // release them in matrix order.
    let legs: Vec<_> = (0..batch.tasks.len())
        .map(|leg| tokio::spawn(run_leg(Arc::clone(&run), leg)))
        .collect();
    let mut failures = Vec::new();
    for (leg, handle) in legs.into_iter().enumerate() {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failures.push(error),
            Err(error) => {
                // The leg's task died before it could settle its own
                // entry: settle it here, with the error it never wrote.
                let error = format!("leg {leg} task failed: {error}");
                state.set_leg(
                    workflow_run_id,
                    batch.tasks[leg].leg,
                    "completed",
                    Some("failure"),
                    Some(&error),
                );
                failures.push(error);
            }
        }
    }
    Ok((root, failures))
}

/// One matrix leg: its `build` job, then — only when the build
/// succeeded, as `build-crate.yml`'s `publish` job is gated — its
/// `publish` job, each recorded as the job and step rows GitHub would
/// serve. A failed leg's error names the leg and the stage.
async fn run_leg(run: Arc<BatchRun>, leg: usize) -> Result<(), String> {
    let _slot = run
        .slots
        .acquire()
        .await
        .expect("the leg slots are never closed");
    let state = &run.state;
    let workflow_run_id = run.workflow_run_id;
    let task = &run.batch.tasks[leg];

    if state.cancel_requested(workflow_run_id) {
        // A queued matrix job whose run was cancelled never gets a
        // runner: its row reads `cancelled`, and the publish `if:`
        // gate skips exactly as a failed build's does.
        state.close_unstarted_job(workflow_run_id, build_job_name(task), "cancelled");
        state.skip_job(workflow_run_id, publish_job_name(task));
        state.set_leg(
            workflow_run_id,
            task.leg,
            "completed",
            Some("cancelled"),
            None,
        );
        return Ok(());
    }
    state.set_leg(workflow_run_id, task.leg, "in_progress", None, None);

    let build_job = state.begin_job(workflow_run_id, build_job_name(task), BUILD_JOB_STEPS);
    let layout = match build_stage(&run, leg).await {
        Ok(layout) => {
            // The glibc-floor report runs `always()` and only reads.
            state.finish_job(
                workflow_run_id,
                build_job,
                "success",
                &["success", "success"],
            );
            layout
        }
        Err(error) => {
            let error = format!("leg {leg} build: {error}");
            state.finish_job(
                workflow_run_id,
                build_job,
                "failure",
                &["failure", "success"],
            );
            state.skip_job(workflow_run_id, publish_job_name(task));
            state.set_leg(
                workflow_run_id,
                task.leg,
                "completed",
                Some("failure"),
                Some(&error),
            );
            return Err(error);
        }
    };

    let publish_job = state.begin_job(workflow_run_id, publish_job_name(task), PUBLISH_JOB_STEPS);
    match publish_stage(&run, leg, &layout).await {
        Ok(()) => {
            state.finish_job(workflow_run_id, publish_job, "success", &["success"]);
            state.set_leg(
                workflow_run_id,
                task.leg,
                "completed",
                Some("success"),
                None,
            );
            Ok(())
        }
        Err(error) => {
            let error = format!("leg {leg} publish: {error}");
            state.finish_job(workflow_run_id, publish_job, "failure", &["failure"]);
            state.set_leg(
                workflow_run_id,
                task.leg,
                "completed",
                Some("failure"),
                Some(&error),
            );
            Err(error)
        }
    }
}

/// The leg's untrusted build stage.
async fn build_stage(run: &BatchRun, leg: usize) -> stow_types::error::Result<LegLayout> {
    let layout = LegLayout::create(&run.root, leg).await?;
    if run.stub {
        return Ok(layout);
    }
    let _runner = run
        .state
        .runners
        .acquire()
        .await
        .expect("the runner pool is never closed");
    // The child is the untrusted build stage: it gets the event file and
    // nothing else, exactly as the production build job does.
    let status = run_build_stage(run, leg, &layout).await?;
    if !status.success() {
        return Err(stow_types::stow_error!(
            "stow-build exited with status {status}: {}",
            stage_error(&layout.build_log_path).await
        ));
    }
    Ok(layout)
}

/// The leg's trusted publish stage: the checks `stow-build publish` makes
/// before its push, then the mock registry standing in for GHCR and
/// cosign, then the leg's records artifact under `(run_id, 1)`.
async fn publish_stage(
    run: &BatchRun,
    leg: usize,
    layout: &LegLayout,
) -> stow_types::error::Result<()> {
    let task = &run.batch.tasks[leg];
    if !run.stub {
        let _runner = run
            .state
            .runners
            .acquire()
            .await
            .expect("the runner pool is never closed");
        // The leg is read back from the event file, as `stow-build
        // publish` reads it, and validated exactly as it validates it:
        // the mock registry below stands in for GHCR and cosign, not for
        // the validation that gates them.
        let event = async_fs::read(&run.event_path).await?;
        let dispatched = crate::task_from_event(&event, &run.event_path, leg)?;
        crate::validated_build_output(&dispatched, &layout.output_dir)
            .await
            .map_err(|error| error.wrap_err("publish-stage validation"))?;
        // `stow-build build` exits non-zero when any cargo phase failed —
        // the outcome is binary: a build that reached here ran to
        // completion and whatever it plans is the whole closure. An
        // artifact-less task skips populate but still publishes its
        // (empty) records artifact — the webhook's existence check must
        // find it.
        if upload_plan_len(&layout.upload_plan_path).await? > 0 {
            populate_mock_registry(&run.exe, &run.state, layout).await?;
        }
    }
    push_records(
        &run.state,
        &task.task_id,
        run.batch.rustc_version.as_str(),
        run.workflow_run_id,
        &layout.records_path,
        &run.exe,
    )
    .await?;
    // The runner a leg stands in for is ephemeral.
    async_fs::remove_dir_all(&layout.root).await?;
    Ok(())
}

/// The build stage's own final error: a `stow-build` that fails exits
/// through `main`'s `Err`, which prints `Error: …` last on stderr.
async fn stage_error(build_log_path: &Path) -> String {
    match async_fs::read_to_string(build_log_path).await {
        Ok(log) => log.rfind("Error: ").map_or_else(
            || "no stage error recorded".to_owned(),
            |at| log[at..].trim_end().to_owned(),
        ),
        Err(error) => format!("read {}: {error}", build_log_path.display()),
    }
}

/// Spawn the untrusted `stow-build build` stage. It receives only the
/// dispatch event file, its leg and a workspace root — the trusted
/// credentials are removed from its environment, as they are absent from
/// the production build job.
async fn run_build_stage(
    run: &BatchRun,
    leg: usize,
    layout: &LegLayout,
) -> stow_types::error::Result<std::process::ExitStatus> {
    Ok(async_process::Command::new(&run.exe)
        .arg("build")
        .arg("--leg")
        .arg(leg.to_string())
        .arg("--output-dir")
        .arg(&layout.output_dir)
        .env_remove("SCHEDULER_URL")
        .env_remove("STOW_EDGE_URL")
        .env_remove("STOW_GITHUB_WEBHOOK_SECRET")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL")
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .env_remove("STOW_OIDC_AUDIENCE")
        .env("STOW_BUILD_WORKSPACE_ROOT", layout.root.join("workspace"))
        .env("GITHUB_EVENT_PATH", &run.event_path)
        .stderr(std::fs::File::create(&layout.build_log_path)?)
        .status()
        .await?)
}

/// Number of entries in the build stage's upload plan; a non-array or
/// empty plan means the task produced nothing to publish.
async fn upload_plan_len(upload_plan_path: &Path) -> stow_types::error::Result<usize> {
    let upload_plan_bytes = async_fs::read(upload_plan_path).await?;
    let upload_plan_json: serde_json::Value = serde_json::from_slice(&upload_plan_bytes)?;
    Ok(upload_plan_json.as_array().map_or(0usize, Vec::len))
}

/// Populate the mock OCI registry from the upload plan and sign with the
/// mock keys, writing the artifact records the records-artifact step then
/// pushes.
async fn populate_mock_registry(
    exe: &Path,
    state: &LocalServerState,
    layout: &LegLayout,
) -> stow_types::error::Result<()> {
    let mock_registry_exe = exe
        .parent()
        .ok_or_else(|| {
            stow_types::stow_error!("cannot determine parent directory of stow-build binary")
        })?
        .join(format!(
            "stow-mock-registry{}",
            std::env::consts::EXE_SUFFIX
        ));
    if !mock_registry_exe.exists() {
        return Err(stow_types::stow_error!(
            "mock registry binary not found at {}",
            mock_registry_exe.display()
        ));
    }
    let populate_status = async_process::Command::new(&mock_registry_exe)
        .arg("populate")
        .arg("--upload-plan")
        .arg(&layout.upload_plan_path)
        .arg("--registry-root")
        .arg(PathBuf::from(&state.mock_registry_root))
        .arg("--private-key")
        .arg(PathBuf::from(&state.mock_private_key_path))
        .arg("--records-out")
        .arg(&layout.records_path)
        .status()
        .await?;
    if populate_status.success() {
        return Ok(());
    }
    Err(stow_types::stow_error!(
        "mock registry populate exited with status {populate_status}"
    ))
}

/// Write the build's records artifact into the mock registry — the same
/// object the production publish stage pushes to GHCR under
/// `records-<rustc>-<task_id hash>-<run_id>-<run_attempt>`, signed by the
/// mock key instead of cosign. The run is the batch dispatch's own
/// `workflow_run_id` at attempt 1 — the run identity the `workflow_run`
/// webhook report below carries, so the edge's records check resolves
/// to this tag.
async fn push_records(
    state: &LocalServerState,
    task_id: &str,
    rustc_version: &str,
    workflow_run_id: u64,
    records_path: &Path,
    exe: &Path,
) -> stow_types::error::Result<()> {
    let mock_registry_exe = exe
        .parent()
        .ok_or_else(|| {
            stow_types::stow_error!("cannot determine parent directory of stow-build binary")
        })?
        .join(format!(
            "stow-mock-registry{}",
            std::env::consts::EXE_SUFFIX
        ));
    // An empty plan leaves no records.json — the records artifact carries
    // the empty set, exactly like production's `push_records(&[])`.
    if !records_path.exists() {
        async_fs::write(records_path, "[]").await?;
    }
    let status = async_process::Command::new(&mock_registry_exe)
        .arg("push-records")
        .arg("--records")
        .arg(records_path)
        .arg("--task-id")
        .arg(task_id)
        .arg("--rustc-version")
        .arg(rustc_version)
        .arg("--run-id")
        .arg(workflow_run_id.to_string())
        .arg("--run-attempt")
        .arg(RUN_ATTEMPT.to_string())
        .arg("--registry-root")
        .arg(PathBuf::from(&state.mock_registry_root))
        .arg("--private-key")
        .arg(PathBuf::from(&state.mock_private_key_path))
        .status()
        .await?;
    if status.success() {
        return Ok(());
    }
    Err(stow_types::stow_error!(
        "mock registry push-records failed with status {status}"
    ))
}

/// The `workflow_run` event a mock run reports — the fields GitHub's
/// payload carries that the edge's signature check, authority boundary
/// and title correlation consume. `run_key` (batch id or request id)
/// identifies the workflow's title context; `workflow_run_id` is the
/// per-dispatch identity shared by the response and callback.
struct WorkflowRunReport {
    /// The id allocated for this dispatch. Every response and webhook for
    /// the run carries this captured value.
    workflow_run_id: u64,
    run_key: String,
    /// The workflow file — `build-batch.yml` or `resolve-request.yml`.
    workflow_file: &'static str,
    display_title: String,
    /// `in_progress` or `completed` — GitHub's `action` field.
    action: &'static str,
    /// `success`/`failure` — present on `completed` deliveries only.
    conclusion: Option<&'static str>,
    /// The run's link — the mock's own `GET /tasks` page.
    html_url: String,
    /// Failure detail worth logging alongside the report.
    error: Option<String>,
}

fn resolve_run_key(dispatch: &RequestDispatch) -> String {
    format!("{}:{}", dispatch.request_id, dispatch.attempt)
}

/// A dispatched batch run's report under `build-batch.yml`'s run-name.
/// `conclusion` and `error` are present on `completed` reports only.
fn batch_workflow_run(
    state: &LocalServerState,
    batch: &BuildBatchPayload,
    workflow_run_id: u64,
    action: &'static str,
    conclusion: Option<&'static str>,
    error: Option<String>,
) -> WorkflowRunReport {
    WorkflowRunReport {
        workflow_run_id,
        run_key: batch.batch_id.to_string(),
        workflow_file: stow_types::trusted_builder::BATCH_WORKFLOW_FILE,
        display_title: stow_types::records::batch_run_title(
            batch.rustc_version.as_str(),
            &batch.batch_id,
        ),
        action,
        conclusion,
        html_url: format!("http://{}/tasks/{workflow_run_id}", state.listen),
        error,
    }
}

/// POST a synthetic `workflow_run` webhook to the edge — the exact
/// event shape and signature header GitHub delivers, so the mock edge
/// verifies the same HMAC the production one does.
async fn post_workflow_run(
    state: &LocalServerState,
    run: &WorkflowRunReport,
) -> stow_types::error::Result<()> {
    const MAX_ATTEMPTS: u32 = 5;
    if let Some(error) = &run.error {
        tracing::warn!(run_key = %run.run_key, %error, "workflow_run reports {:?}", run.conclusion);
    }
    // The production pin: same path/branch/event/repository fields the
    // webhook requires, with the run title the workflow stamps.
    let payload = serde_json::json!({
        "action": run.action,
        "repository": {"full_name": stow_types::trusted_builder::REPOSITORY},
        "workflow_run": {
            "id": run.workflow_run_id,
            // The local server models a fresh run per dispatch — every
            // run is attempt 1, the same attempt the records push above
            // tags the artifact under.
            "run_attempt": RUN_ATTEMPT,
            "name": run.workflow_file,
            "path": format!(".github/workflows/{}", run.workflow_file),
            "event": "workflow_dispatch",
            "display_title": run.display_title,
            "head_branch": stow_types::trusted_builder::BRANCH,
            "conclusion": run.conclusion,
            "html_url": run.html_url,
            "head_repository": {"full_name": stow_types::trusted_builder::REPOSITORY},
        },
    });
    let body = serde_json::to_vec(&payload)?;
    let signature = {
        let mut mac = HmacSha256::new_from_slice(state.webhook_secret.as_bytes())
            .map_err(|error| stow_types::stow_error!("init webhook HMAC: {error}"))?;
        mac.update(&body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    };
    let url = format!(
        "{}/api/v1/github/workflow-run",
        state.edge_url.trim_end_matches('/')
    );
    let mut last_error: Option<stow_types::error::Error> = None;
    for attempt in 0..MAX_ATTEMPTS {
        let attempt_result = async {
            let mut client = zenwave::client();
            client
                .post(&url)?
                .header("X-GitHub-Event", "workflow_run")?
                .header("X-Hub-Signature-256", &signature)?
                .header("Content-Type", "application/json")?
                .bytes_body(body.clone())
                .await?
                .error_for_status()
                .await?;
            Ok::<(), zenwave::Error>(())
        }
        .await;
        match attempt_result {
            Ok(()) => return Ok(()),
            Err(error) => {
                state.record_delivery_error(run.workflow_run_id, &error.to_string());
                last_error = Some(stow_types::stow_error!("POST {url}: {error}"));
                if attempt + 1 < MAX_ATTEMPTS {
                    sleep(Duration::from_millis(250)).await;
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        stow_types::stow_error!("post_workflow_run: all {MAX_ATTEMPTS} attempts failed")
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use stow_types::api::{BuildBatchPayload, TaskHash};
    use stow_types::runs::{
        LegFailure, LegJobKind, LegJobName, LegOutcome, RunFailure, RunJobRow, VERDICT_STEPS,
        classify_legs,
    };

    use tokio::sync::Semaphore;

    use super::{
        BUILD_JOB_STEPS, BatchRun, JobsQuery, LocalServerState, PUBLISH_JOB_STEPS, RUN_ATTEMPT,
        RecordedJob, WorkflowRunReport, attempt_jobs_page, attempt_jobs_response, build_job_name,
        cancel_response, dispatch_response, publish_job_name, run_leg, run_response,
    };
    use stow_types::local_ci::{LocalCiSeededConclusion, LocalCiSeededRun, LocalCiSeededRuns};

    use skyzen::StatusCode;

    fn state() -> LocalServerState {
        LocalServerState::new(String::new(), String::new(), String::new(), String::new())
    }

    #[test]
    fn repeated_dispatches_keep_distinct_captured_run_ids() {
        let state = state();
        let first = WorkflowRunReport {
            workflow_run_id: state.allocate_id(),
            run_key: "batch".to_owned(),
            workflow_file: "build-batch.yml",
            display_title: "1.86.0-batch".to_owned(),
            action: "completed",
            conclusion: None,
            html_url: String::new(),
            error: None,
        };
        let first_response = dispatch_response(&first);
        state.mark_run(
            first.workflow_run_id,
            first.workflow_file,
            &first.display_title,
            "in_progress",
            None,
        );

        let second = WorkflowRunReport {
            workflow_run_id: state.allocate_id(),
            run_key: first.run_key.clone(),
            workflow_file: first.workflow_file,
            display_title: first.display_title.clone(),
            action: first.action,
            conclusion: None,
            html_url: String::new(),
            error: None,
        };
        let second_response = dispatch_response(&second);
        state.mark_run(
            second.workflow_run_id,
            second.workflow_file,
            &second.display_title,
            "in_progress",
            None,
        );

        assert_ne!(first.workflow_run_id, second.workflow_run_id);
        assert_eq!(first_response.workflow_run_id, first.workflow_run_id);
        assert_eq!(second_response.workflow_run_id, second.workflow_run_id);
        assert_eq!(
            state.runs.lock().expect("runs mutex poisoned").len(),
            2,
            "repeated batch keys retain both run records"
        );
    }

    /// The two jobs' step rows are exactly the verdict steps, so the
    /// classifier sees every step the contract names.
    #[test]
    fn job_steps_cover_the_verdict_steps() {
        let recorded: Vec<&str> = BUILD_JOB_STEPS
            .iter()
            .chain(PUBLISH_JOB_STEPS)
            .copied()
            .collect();
        assert_eq!(recorded, VERDICT_STEPS);
    }

    /// A one-leg batch run for `run_leg`: `exe` names the build stage
    /// binary and the directory the mock registry binary sits in.
    fn batch_run(state: &LocalServerState, exe: &std::path::Path, stub: bool) -> Arc<BatchRun> {
        let batch: BuildBatchPayload =
            serde_json::from_str(&crate::batch_fixture::encoded_batch(&["serde"], 1)).unwrap();
        let root = exe.parent().unwrap().join("run");
        std::fs::create_dir_all(&root).unwrap();
        let event_path = root.join("event.json");
        std::fs::write(
            &event_path,
            serde_json::to_vec(&serde_json::json!({
                "inputs": { "batch": batch.encode_dispatch_batch().unwrap() }
            }))
            .unwrap(),
        )
        .unwrap();
        Arc::new(BatchRun {
            state: state.clone(),
            batch,
            workflow_run_id: state.allocate_id(),
            root,
            event_path,
            slots: Semaphore::new(1),
            stub,
            exe: exe.to_path_buf(),
        })
    }

    /// An executable shell script at `path` that exits `code`.
    fn script(path: &std::path::Path, code: i32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, format!("#!/bin/sh\nexit {code}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// The recorded jobs of `run`, read the way the edge reads GitHub's
    /// jobs page, classified for the batch's one leg.
    fn classified(state: &LocalServerState, run: &BatchRun) -> LegOutcome {
        let page = serde_json::json!({
            "jobs": state.jobs.lock().unwrap()[&run.workflow_run_id],
        });
        let jobs: Vec<RunJobRow> = serde_json::from_value::<stow_types::runs::RunJobsPage>(page)
            .unwrap()
            .jobs;
        let names: Vec<_> = jobs
            .iter()
            .map(|job| LegJobName::parse(&job.name).unwrap_or_else(|| panic!("{}", job.name)))
            .collect();
        let hash = run.batch.tasks[0].task_hash.clone();
        assert!(names.iter().all(|name| name.leg == 0 && name.hash == hash));
        assert_eq!(names[0].kind, LegJobKind::Build);
        let expected: Vec<TaskHash> = vec![hash];
        let conclusion = if jobs
            .iter()
            .any(|job| job.conclusion.as_deref() == Some("failure"))
        {
            "failure"
        } else {
            "success"
        };
        classify_legs(
            &expected,
            conclusion,
            &jobs,
            time::OffsetDateTime::now_utc(),
        )
        .unwrap()
        .remove(0)
    }

    #[test]
    fn leg_job_names_follow_the_reusable_workflow_matrix_naming() {
        let batch: BuildBatchPayload =
            serde_json::from_str(&crate::batch_fixture::encoded_batch(&["serde"], 1)).unwrap();
        let leg = &batch.tasks[0];
        assert_eq!(
            build_job_name(leg),
            format!(
                "leg 0 / build #0 serde 1.0.0 (x86_64-unknown-linux-gnu) {}",
                leg.task_hash
            )
        );
        assert_eq!(
            publish_job_name(leg),
            format!("leg 0 / publish #0 {}", leg.task_hash)
        );
    }

    /// A stubbed leg whose records push succeeds records two `success`
    /// jobs the leg classifier accepts as a success.
    #[tokio::test]
    async fn a_landed_leg_records_two_successful_jobs() {
        let dir = tempfile::tempdir().unwrap();
        script(&dir.path().join("stow-mock-registry"), 0);
        let state = state();
        let run = batch_run(&state, &dir.path().join("stow-build"), true);
        run_leg(Arc::clone(&run), 0).await.unwrap();
        assert!(matches!(
            classified(&state, &run),
            LegOutcome::Succeeded {
                publish_attempt: 1,
                ..
            }
        ));
        let jobs = state.jobs.lock().unwrap();
        let steps: Vec<_> = jobs[&run.workflow_run_id]
            .iter()
            .flat_map(|job| job.steps.iter().map(|step| step.name.as_str()))
            .collect();
        assert_eq!(steps, VERDICT_STEPS);
        drop(jobs);
    }

    /// A recorded job row for the paging tests — the page decoder
    /// reads only the envelope and the rows.
    fn recorded_job(id: u64) -> RecordedJob {
        RecordedJob {
            id,
            name: format!("job {id}"),
            status: "completed",
            conclusion: Some("success"),
            started_at: None,
            completed_at: None,
            run_attempt: RUN_ATTEMPT,
            html_url: String::new(),
            steps: Vec::new(),
        }
    }

    /// A jobs page response's row count and raw `Link` header.
    async fn page_parts(response: skyzen::Response) -> (usize, Option<String>) {
        let link = response
            .headers()
            .get("link")
            .map(|value| value.to_str().expect("link is ASCII").to_owned());
        let body: serde_json::Value = serde_json::from_slice(
            &response
                .into_body()
                .into_bytes()
                .await
                .expect("page body reads"),
        )
        .expect("jobs page is JSON");
        (body["jobs"].as_array().expect("jobs array").len(), link)
    }

    /// A 40-leg batch's 80 jobs page at the request's `per_page` — the
    /// default 30 gives three pages and `Link`'s `rel="next"` keeps
    /// walking on the mock's own origin until the last.
    #[tokio::test]
    async fn attempt_jobs_pages_at_the_requested_size() {
        let mut state = state();
        state.listen = "127.0.0.1:28124".parse().unwrap();
        let run_id = state.allocate_id();
        let jobs: Vec<RecordedJob> = (0..80).map(recorded_job).collect();

        // The default page is GitHub's 30; `next` stays on the mock's
        // own origin so the edge's scoped pager follows it.
        let (len, link) = page_parts(attempt_jobs_page(
            &state,
            run_id,
            RUN_ATTEMPT,
            &jobs,
            &JobsQuery {
                per_page: None,
                page: None,
            },
        ))
        .await;
        assert_eq!(len, 30);
        let next = stow_types::runs::link_next(link.as_deref()).expect("page 1 has next");
        assert!(
            next.starts_with(&format!("http://{}/", state.listen)),
            "{next} stays on the mock's origin"
        );
        assert!(next.contains("page=2"), "{next}");

        // A middle page links both ways: `next`/`last` onward,
        // `first`/`prev` back.
        let (len, link) = page_parts(attempt_jobs_page(
            &state,
            run_id,
            RUN_ATTEMPT,
            &jobs,
            &JobsQuery {
                per_page: Some(30),
                page: Some(2),
            },
        ))
        .await;
        assert_eq!(len, 30);
        let link = link.expect("page 2 links");
        assert!(
            stow_types::runs::link_next(Some(&link))
                .expect("page 2 has next")
                .contains("page=3")
        );
        assert!(link.contains("rel=\"last\""));
        assert!(link.contains("rel=\"first\""));
        assert!(link.contains("rel=\"prev\""));

        // The last page ends the walk — no `next`.
        let (len, link) = page_parts(attempt_jobs_page(
            &state,
            run_id,
            RUN_ATTEMPT,
            &jobs,
            &JobsQuery {
                per_page: Some(30),
                page: Some(3),
            },
        ))
        .await;
        assert_eq!(len, 20);
        assert!(stow_types::runs::link_next(link.as_deref()).is_none());

        // `per_page=100` — the edge's own request — lands all 80 jobs
        // of a 40-leg batch on one page.
        let (len, link) = page_parts(attempt_jobs_page(
            &state,
            run_id,
            RUN_ATTEMPT,
            &jobs,
            &JobsQuery {
                per_page: Some(100),
                page: Some(1),
            },
        ))
        .await;
        assert_eq!(len, 80);
        assert!(link.is_none());
    }

    /// A run the mock never held — or an attempt it never ran — is
    /// GitHub's 404 on every run endpoint.
    #[test]
    fn run_endpoints_404_unknown_runs_and_attempts() {
        let state = state();
        let run_id = state.allocate_id();
        state.mark_run(
            run_id,
            "build-batch.yml",
            "1.99.0-b0123",
            "in_progress",
            None,
        );
        assert_eq!(run_response(&state, run_id).status(), StatusCode::OK);
        assert_eq!(
            run_response(&state, state.allocate_id()).status(),
            StatusCode::NOT_FOUND
        );
        let query = |page| JobsQuery {
            per_page: None,
            page,
        };
        assert_eq!(
            attempt_jobs_response(&state, state.allocate_id(), RUN_ATTEMPT, &query(None)).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            attempt_jobs_response(&state, run_id, RUN_ATTEMPT + 1, &query(None)).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            cancel_response(&state, run_id).status(),
            StatusCode::ACCEPTED
        );
        assert_eq!(
            cancel_response(&state, state.allocate_id()).status(),
            StatusCode::NOT_FOUND
        );
    }

    /// A queued leg of a cancelled run records the GitHub shape — its
    /// build `cancelled`, its publish `skipped`, the leg
    /// `completed`/`cancelled` — and never spawns its stages.
    #[tokio::test]
    async fn a_cancelled_run_stops_legs_that_never_started() {
        let dir = tempfile::tempdir().unwrap();
        let state = state();
        let run = batch_run(&state, &dir.path().join("stow-build"), true);
        state.mark_run(
            run.workflow_run_id,
            "build-batch.yml",
            "1.99.0-b0123",
            "in_progress",
            None,
        );
        state.seed_legs(run.workflow_run_id, &run.batch);
        assert_eq!(
            cancel_response(&state, run.workflow_run_id).status(),
            StatusCode::ACCEPTED
        );
        run_leg(Arc::clone(&run), 0).await.unwrap();
        let jobs = state.jobs.lock().unwrap();
        let conclusions: Vec<_> = jobs[&run.workflow_run_id]
            .iter()
            .map(|job| job.conclusion)
            .collect();
        drop(jobs);
        assert_eq!(conclusions, [Some("cancelled"), Some("skipped")]);
        let leg = state.runs.lock().unwrap()[&run.workflow_run_id.to_string()].legs[0].clone();
        assert_eq!(leg.status, "completed");
        assert_eq!(leg.conclusion.as_deref(), Some("cancelled"));
    }

    /// A build stage that exits non-zero fails the `Run the untrusted
    /// build stage` step — the crate's verdict — and skips the publish
    /// job.
    #[tokio::test]
    async fn a_failed_build_is_a_verdict_and_skips_publish() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("stow-build");
        script(&exe, 3);
        let state = state();
        let run = batch_run(&state, &exe, false);
        let error = run_leg(Arc::clone(&run), 0).await.unwrap_err();
        assert!(error.starts_with("leg 0 build:"), "{error}");
        match classified(&state, &run) {
            LegOutcome::Failed(LegFailure::Run(RunFailure::Verdict { step, .. })) => {
                assert_eq!(step, VERDICT_STEPS[0]);
            }
            other => panic!("expected a build verdict, got {other:?}"),
        }
        let jobs = state.jobs.lock().unwrap();
        assert_eq!(jobs[&run.workflow_run_id][1].conclusion, Some("skipped"));
    }

    /// A records push that fails fails the `Run the trusted publish
    /// stage` step.
    #[tokio::test]
    async fn a_failed_publish_is_a_verdict_on_the_publish_step() {
        let dir = tempfile::tempdir().unwrap();
        script(&dir.path().join("stow-mock-registry"), 1);
        let state = state();
        let run = batch_run(&state, &dir.path().join("stow-build"), true);
        let error = run_leg(Arc::clone(&run), 0).await.unwrap_err();
        assert!(error.starts_with("leg 0 publish:"), "{error}");
        match classified(&state, &run) {
            LegOutcome::Failed(LegFailure::Run(RunFailure::Verdict { step, .. })) => {
                assert_eq!(step, VERDICT_STEPS[2]);
            }
            other => panic!("expected a publish verdict, got {other:?}"),
        }
    }

    fn seeded(
        run_id: Option<u64>,
        task_id: &str,
        conclusion: LocalCiSeededConclusion,
    ) -> stow_types::local_ci::LocalCiSeededRun {
        stow_types::local_ci::LocalCiSeededRun {
            workflow_run_id: run_id,
            rustc_version: stow_types::identity::WireRustcVersion::parse("1.86.0".to_owned())
                .unwrap(),
            batch_id: task_id[32..].parse().unwrap(),
            legs: vec![task_id.to_owned()],
            conclusion,
        }
    }

    /// Assign and record `runs` the way the route does, records aside.
    fn record(state: &LocalServerState, runs: Vec<LocalCiSeededRun>) -> Vec<u64> {
        let seeded = LocalCiSeededRuns { runs };
        let ids = state.seeded_run_ids(&seeded).unwrap();
        for (run, &run_id) in seeded.runs.iter().zip(&ids) {
            state.record_seeded_run(run, run_id);
        }
        ids
    }

    /// The recorded jobs of seeded run `run_id`, classified for its one
    /// leg under the run's recorded conclusion.
    fn seeded_outcome(state: &LocalServerState, run_id: u64, task_id: &str) -> LegOutcome {
        let conclusion = state.runs.lock().unwrap()[&run_id.to_string()]
            .conclusion
            .clone()
            .unwrap();
        let jobs: Vec<RunJobRow> = serde_json::from_value::<stow_types::runs::RunJobsPage>(
            serde_json::json!({ "jobs": state.jobs.lock().unwrap()[&run_id] }),
        )
        .unwrap()
        .jobs;
        let hash = TaskHash::of(task_id);
        assert!(jobs.iter().all(|job| {
            LegJobName::parse(&job.name).is_some_and(|name| name.leg == 0 && name.hash == hash)
        }));
        classify_legs(&[hash], &conclusion, &jobs, time::OffsetDateTime::now_utc())
            .unwrap()
            .remove(0)
    }

    /// A seeded run reads back as a finished `build-batch.yml` run
    /// titled for its batch, its jobs page classifies the leg as a
    /// success, and the allocator moves past it.
    #[test]
    fn a_seeded_run_serves_a_successful_batch_jobs_page() {
        let state = state();
        let task_id = format!("{:064x}", 97_502_u64);
        let run = seeded(Some(97_502), &task_id, LocalCiSeededConclusion::Success);
        assert_eq!(record(&state, vec![run.clone()]), [97_502]);

        let recorded = state.runs.lock().unwrap()["97502"].clone();
        assert_eq!(
            recorded.display_title,
            stow_types::records::batch_run_title("1.86.0", &run.batch_id)
        );
        assert_eq!(recorded.path, ".github/workflows/build-batch.yml");
        assert_eq!(recorded.conclusion.as_deref(), Some("success"));
        assert!(matches!(
            seeded_outcome(&state, 97_502, &task_id),
            LegOutcome::Succeeded { .. }
        ));
        assert!(state.allocate_id() > 97_502);
    }

    /// A run seeded as failed settles at once as a verdict failure of
    /// its build — the step rows are complete, so no settle window
    /// defers it — and its publish job is skipped.
    #[test]
    fn a_seeded_failed_run_serves_a_settled_verdict_failure() {
        let state = state();
        let task_id = format!("{:064x}", 41_u64);
        let [run_id] = record(
            &state,
            vec![seeded(None, &task_id, LocalCiSeededConclusion::Failure)],
        )[..] else {
            panic!("one run seeded");
        };
        assert_eq!(
            state.runs.lock().unwrap()[&run_id.to_string()]
                .conclusion
                .as_deref(),
            Some("failure")
        );
        match seeded_outcome(&state, run_id, &task_id) {
            LegOutcome::Failed(LegFailure::Run(RunFailure::Verdict { step, .. })) => {
                assert_eq!(step, VERDICT_STEPS[0]);
            }
            other => panic!("expected a build verdict, got {other:?}"),
        }
        assert!(
            state.jobs.lock().unwrap()[&run_id]
                .iter()
                .any(|job| job.conclusion == Some("skipped"))
        );
    }

    /// An unnamed run takes an id the allocator hands out after every
    /// named one, and a later dispatch's id lands above it.
    #[test]
    fn an_unnamed_seeded_run_is_allocated_above_the_named_ones() {
        let state = state();
        let named = format!("{:064x}", 900_u64);
        let unnamed = format!("{:064x}", 901_u64);
        let ids = record(
            &state,
            vec![
                seeded(None, &unnamed, LocalCiSeededConclusion::Success),
                seeded(Some(900), &named, LocalCiSeededConclusion::Success),
            ],
        );
        assert_eq!(ids[1], 900);
        assert!(ids[0] > 900, "{ids:?}");
        assert!(state.allocate_id() > ids[0]);
    }

    /// Only a succeeded run's legs publish records: the failed run's
    /// leg pushes nothing, so the mock registry binary is never run for
    /// it — a registry that refuses every push fails only the success.
    #[tokio::test]
    async fn only_succeeded_legs_publish_records() {
        let dir = tempfile::tempdir().unwrap();
        script(&dir.path().join("stow-mock-registry"), 1);
        let exe = dir.path().join("stow-build");
        let state = state();
        let task_id = format!("{:064x}", 77_u64);
        let failed = LocalCiSeededRuns {
            runs: vec![seeded(None, &task_id, LocalCiSeededConclusion::Failure)],
        };
        let ids = state.seeded_run_ids(&failed).unwrap();
        state
            .publish_seeded_records(&failed, &ids, &exe)
            .await
            .unwrap();
        let succeeded = LocalCiSeededRuns {
            runs: vec![seeded(None, &task_id, LocalCiSeededConclusion::Success)],
        };
        let ids = state.seeded_run_ids(&succeeded).unwrap();
        assert!(
            state
                .publish_seeded_records(&succeeded, &ids, &exe)
                .await
                .is_err()
        );
    }

    /// A seeded id at or below one the server already allocated, a
    /// repeated id, a legless run and an empty request are refused
    /// before anything is recorded.
    #[test]
    fn seeding_refuses_ids_the_server_could_reuse() {
        let state = state();
        let task_id = format!("{:064x}", 7_u64);
        let success = LocalCiSeededConclusion::Success;
        let allocated = state.allocate_id();
        let clash = LocalCiSeededRuns {
            runs: vec![seeded(Some(allocated), &task_id, success)],
        };
        assert!(state.seeded_run_ids(&clash).is_err());
        let twice = LocalCiSeededRuns {
            runs: vec![
                seeded(Some(50), &task_id, success),
                seeded(Some(50), &task_id, success),
            ],
        };
        assert!(state.seeded_run_ids(&twice).is_err());
        let mut legless = seeded(None, &task_id, success);
        legless.legs.clear();
        assert!(
            state
                .seeded_run_ids(&LocalCiSeededRuns {
                    runs: vec![legless]
                })
                .is_err()
        );
        let empty = LocalCiSeededRuns { runs: Vec::new() };
        assert!(state.seeded_run_ids(&empty).is_err());
        assert!(state.runs.lock().unwrap().is_empty());
    }
}
