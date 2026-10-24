//! `stow-admin preheat manual` — the operator-driven preheat of
//! water-rs/stow#455. Cloudflare may be fully offline: the driver
//! resolves the graph in-process, layers it topologically, packs each
//! layer's dispatchable nodes into `build-crate.yml` runs
//! and dispatches them straight through the GitHub API (or the local
//! CI server under `--dispatch-url`), and lets the registry be the only
//! record store — the scheduler's `tasks/submit` and every edge route
//! stay untouched.
//!
//! Resume is index-rooted, not state-file-rooted: on startup the driver
//! pulls every published `(target, rustc_version)` index slice and marks
//! the nodes it already serves, so a re-run computes only the remaining
//! work. Runs a previous invocation dispatched are adopted by
//! `display_title` rather than re-dispatched — except a failure that ran
//! code `main` no longer carries, which says nothing about the code a
//! dispatch runs now and is dispatched again. A failure outside the
//! steps that run the crate is runner infrastructure, not the node's
//! verdict: the run's failed jobs are rerun in place (bounded by
//! `MAX_RUN_ATTEMPTS`) and the node stays open.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use clap::Args;
use futures_util::{StreamExt as _, TryStreamExt as _};
use oci_client::manifest::OciImageManifest;
use stow_types::api::{
    BuildTaskPayload, EnqueueDependency, EnqueueRequest, RunnerFamily, runner_family,
};
use stow_types::ci::{
    CiInterface, DispatchError as CiDispatchError, STOW_MACOS_RUNNER_BUDGET, STOW_RUNNER_BUDGET,
};
use stow_types::identity::{CrateName, CrateVersion, TargetTriple, WireRustcVersion};
use stow_types::index::{ArtifactIndexRow, STOW_INDEX_MEDIA_TYPE, index_tag};
use stow_types::public_cache::{UnitInvocation, required_unit_shapes};
use stow_types::records::parse_run_title;
use stow_types::registry::{CacheRepository, cache_repository};
use stow_types::runs::{GITHUB_CLOCK_ALLOWANCE, RunFailure};
use stow_types::stow_error;
use stow_types::task_graph::TaskNodeIdentity;
use stow_types::transient::Backoff;
use stow_types::trusted_builder::{
    BRANCH, INDEX_CERTIFICATE_IDENTITY, WORKFLOW_FILE, WORKFLOW_NAME,
};

use crate::ci::ZenwaveTransport;
use crate::github::{WorkflowRunRow, WriteFailure};
use crate::render::{self, Output};
use crate::runs::{TaskOutcome, classify_page};

/// The build-crate runs poll cadence.
const RUN_POLL_SECONDS: u64 = 30;
/// The layer progress line's cadence — every second poll tick.
const LAYER_PROGRESS_SECONDS: u64 = 60;
/// The published-slice poll cadence after an index-publish dispatch.
const INDEX_POLL_SECONDS: u64 = 60;
/// How long a layer's index publish may take before the driver fails —
/// the publish job itself is minutes; the headroom covers runner queues.
const PUBLISH_TIMEOUT_MINUTES: u64 = 120;
/// GitHub may take a few seconds to materialize a dispatched run — a
/// task whose run does not appear inside this window is a real error.
const RUN_GRACE_MINUTES: u64 = 10;
/// The index slices ride this workflow's dispatch.
const INDEX_PUBLISH_WORKFLOW: &str = "index-publish.yml";
/// Concurrent slice pulls while reading coverage — `CI_TARGET_TRIPLES`
/// stays under this, but the bound stands regardless. Workflow
/// dispatches never fan out: GitHub's secondary rate limits ask for
/// serial mutating requests.
const SLICE_PULL_CONCURRENCY: usize = 8;
/// How far back `workflow_run` adoption looks when `--adopt-since`
/// is not given.
const ADOPT_SINCE_DEFAULT_HOURS: i64 = 24;
/// How many attempts one run gets before a failure is final —
/// `rerun-failed-jobs` bumps the run's `run_attempt`, so a failure
/// observed at this count is the node's verdict even when its step
/// is infrastructure.
const MAX_RUN_ATTEMPTS: u64 = 3;

/// `stow-admin preheat manual` arguments.
#[derive(Debug, Args)]
pub struct ManualArgs {
    /// Crate list file — one `name` or `name@version` line per entry; a
    /// bare name resolves to the newest non-yanked release. `#`
    /// comments and blank lines are ignored.
    #[arg(long, conflicts_with = "projects")]
    crates: Option<PathBuf>,
    /// A projects list in the `preheat/projects.toml` shape —
    /// `[[project]] repo = "https://github.com/<owner>/<name>"`.
    #[arg(long)]
    projects: Option<PathBuf>,
    /// Pinned source trees (stow#558) for `--projects` entries whose
    /// git checkout does not carry every Rust input — see
    /// `preheat/source-trees.toml`. Only meaningful with `--projects`.
    #[arg(long, requires = "projects", conflicts_with_all = ["crates", "dirs"])]
    source_trees: Option<PathBuf>,
    /// Comma-separated local project directories — resolved like a
    /// `--projects` entry (cargo's own resolver, the tree's `Cargo.lock`
    /// dropped). Each directory is mutated: pass a disposable copy.
    /// The mock lane seeds the wave with a consumer project's own graph.
    #[arg(long, conflicts_with_all = ["crates", "projects"], value_delimiter = ',')]
    dirs: Option<Vec<PathBuf>>,
    /// The stable rustc every task pins — `1.85.0`-style.
    #[arg(long)]
    rustc_version: String,
    /// Runner slots in flight at once — one `build-crate.yml` run
    /// holds one slot, bounded by the shared
    /// [`STOW_RUNNER_BUDGET`] margin so the rest of the org keeps
    /// runners (stow#877).
    #[arg(long, default_value_t = STOW_RUNNER_BUDGET)]
    in_flight: u32,
    /// Comma-separated CI target triples to resolve and dispatch for —
    /// defaults to every `CI_TARGET_TRIPLES` entry. The mock lane
    /// narrows it to the host triple.
    #[arg(long, value_delimiter = ',')]
    targets: Option<Vec<String>>,
    /// Dispatch through the local CI server (`stow-build serve`)
    /// instead of GitHub — the mock-e2e path. Run state polls
    /// `GET {url}/tasks`; the index publish runs `stow-admin index
    /// export|publish` as subprocesses against the mock registry.
    #[arg(long)]
    dispatch_url: Option<String>,
    /// Edge URL forwarded to index-publish's `stow_edge_url` input —
    /// the slice report runs only when this names a live edge.
    /// Defaults to `STOW_EDGE_URL`.
    #[arg(long, env = "STOW_EDGE_URL")]
    edge_url: Option<String>,
    /// How far back the GitHub runs list may reach to adopt a
    /// previous invocation's dispatches — an RFC 3339 timestamp,
    /// defaulting to 24 h ago. Runs older than this are never the
    /// wave's and are not adopted.
    #[arg(long, value_parser = parse_adopt_since)]
    adopt_since: Option<time::OffsetDateTime>,
    /// Resolve the cohort, encode every wave payload and report the
    /// dispatch-input sizes, then exit — nothing is dispatched and no
    /// GitHub token or dispatch URL is needed (stow#588).
    #[arg(long)]
    dry_run: bool,
}

/// `--adopt-since`'s RFC 3339 parse.
fn parse_adopt_since(raw: &str) -> Result<time::OffsetDateTime, String> {
    time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
        .map_err(|error| format!("{raw}: {error}"))
}

/// A dispatch sent but never answered clearly — a 5xx or a connection
/// that failed after the request left, so whether the write happened
/// is unknown. `wall` bounds the resolution listing's `created` window
/// and each candidate run's acceptance floor; `instant` runs the
/// `RUN_GRACE_MINUTES` deadline after which the node returns to unsent
/// and the loop dispatches it again.
struct UnansweredDispatch {
    /// The wall clock taken just before the request was sent.
    wall: time::OffsetDateTime,
    /// The monotonic instant of the same moment.
    instant: tokio::time::Instant,
}

/// A `rerun-failed-jobs` write sent but never answered clearly. The
/// poll that sees the run take the rerun pushes the [`RerunRecord`]
/// the success path would have pushed — `tasks` names the task the
/// ask was for, with the job and step its failure named.
struct PendingRerun {
    /// The failed `run_attempt` the rerun was asked on.
    attempt: u64,
    /// When the write went out — the `RUN_GRACE_MINUTES` deadline after
    /// which an unchanged run is classified again, resending the ask.
    asked_at: tokio::time::Instant,
    /// The task that earned the ask — one task is one run.
    task: RerunTask,
}

/// The task a rerun was asked for: the node's task id, the job it
/// failed in and that job's failed step (or conclusion) when it had
/// one — the fields a [`RerunRecord`] reports.
struct RerunTask {
    task_id: String,
    job: String,
    step: Option<String>,
}

/// The layer's write gate: one outage budget shared by every mutating
/// call the wave makes — node dispatches and failed-job reruns alike —
/// plus the earliest instant the next write may go out. A write whose
/// answer settled nothing pauses sends until the backoff's wait
/// elapses; a write that succeeded restores the whole budget. Reads
/// never consult it: bound-run polls and unresolved-dispatch
/// resolution run every iteration regardless.
struct WriteGate {
    backoff: Backoff,
    /// The earliest `Instant` the next write may send — the backoff's
    /// handed-out wait turned into a deadline.
    next_at: Option<tokio::time::Instant>,
}

/// The wait a failed write asks for: a rate limit's own stated wait is
/// honored in full — the write provably did not happen, and a rate
/// limit is not an unanswered write that spends the outage budget —
/// while every other unsettled answer asks the budget for its next
/// wait.
fn write_hold(backoff: &mut Backoff, failure: &WriteFailure) -> Option<std::time::Duration> {
    match failure {
        WriteFailure::RateLimited {
            hint: Some(wait), ..
        } => Some(*wait),
        _ => backoff.next_wait(failure.hint()),
    }
}

impl WriteGate {
    const fn new() -> Self {
        Self {
            backoff: Backoff::outage(),
            next_at: None,
        }
    }

    /// Whether a write may go out now.
    fn open(&self) -> bool {
        self.next_at
            .is_none_or(|at| tokio::time::Instant::now() >= at)
    }

    /// A write whose answer was clear restores the whole outage budget.
    const fn confirmed(&mut self) {
        *self = Self::new();
    }

    /// A write whose answer settled nothing takes [`write_hold`]'s
    /// wait: `Some` pauses sends until it elapses, `None` is the
    /// wave's error — GitHub writes stayed unanswerable past the
    /// outage bound.
    fn hold(&mut self, failure: &WriteFailure) -> stow_types::error::Result<()> {
        match write_hold(&mut self.backoff, failure) {
            Some(wait) => {
                self.next_at = Some(tokio::time::Instant::now() + wait);
                tracing::warn!(%failure, wait = ?wait, "GitHub write unanswered; writes paused");
                Ok(())
            }
            None => Err(stow_error!(
                "GitHub writes stayed unanswerable for the outage bound; last failure: {failure}"
            )),
        }
    }
}

/// The mutable wave state every fold, resolution and send pass inside
/// `drive_layer` shares: the node map, the open-task set, the bound
/// runs, the rerun report and the write gate.
struct Wave<'a> {
    nodes: &'a mut BTreeMap<String, NodeRun>,
    open: &'a mut BTreeSet<String>,
    runs: &'a mut HashMap<String, BoundRun>,
    reruns: &'a mut Vec<RerunRecord>,
    gate: &'a mut WriteGate,
}

/// One node's run to completion — one `build-crate.yml` run is one
/// task; the outcome surfaces through its jobs.
struct NodeRun {
    request: EnqueueRequest,
    /// `Some(url)` once a run exists for the node — absent while the
    /// dispatch is still inside GitHub's registration grace.
    run_url: Option<String>,
    /// The run the node's task is bound to — guards every outcome
    /// fold: only the bound run may settle the node.
    workflow_run_id: Option<u64>,
    /// The node rides a sent or adopted run — it holds its slot and
    /// is never sent twice.
    dispatched: bool,
    done: bool,
    failed: bool,
    /// The failed ancestor that blocks this node — a node whose
    /// dependency failed, or was itself blocked behind one, is skipped
    /// before its layer dispatches.
    blocked_by: Option<String>,
}

/// A run the wave dispatched or adopted — the slot holder and the
/// poll unit. One task is one run and holds one runner slot while it
/// lives, so `--in-flight` is the count of entries; a settled run's
/// entry drops and its slot frees.
struct BoundRun {
    /// The wave node's task id — the dispatch's identity and the run
    /// title's `<rustc>-<task_id>` tail.
    task_id: String,
    /// The run id once bound — absent while a minted dispatch's answer
    /// is still ambiguous.
    workflow_run_id: Option<u64>,
    /// `Some(url)` once a state row names it.
    run_url: Option<String>,
    /// The validator for this run's bound `actions/runs/{id}` read —
    /// a 304 keeps the cached row and costs nothing against the
    /// primary rate budget.
    etag: Option<String>,
    /// The last state the bound run reported — a 304's stand-in.
    latest: Option<RunState>,
    /// A state row was observed for the run id — the 404 and untitled
    /// graces read it.
    observed: bool,
    /// A dispatch whose answer was ambiguous — the write may or may not
    /// have reached the dispatcher, so the task counts as dispatched
    /// (it holds its slot and is never sent again) while the
    /// resolution listing settles it. `None` when the last send's
    /// answer was clear.
    unresolved: Option<UnansweredDispatch>,
    /// A `rerun-failed-jobs` write whose answer was ambiguous — what
    /// was asked, held until a later row says whether the run took it.
    pending_rerun: Option<PendingRerun>,
    /// The confirmed dispatch's send time — `RUN_GRACE_MINUTES`
    /// applies per run.
    dispatched_at: Option<std::time::Instant>,
}

/// The wave's CI handle: the shared [`CiInterface`] every submit and
/// occupancy read goes through (stow#877), plus the backend particulars
/// `refresh_head`/`list_runs`/`poll_bound` still read — GitHub's run
/// rows through the same token, the local server's through its
/// `/tasks` list.
struct Dispatch {
    /// The one privileged CI interface this wave drives.
    interface: CiInterface<ZenwaveTransport>,
    /// What the run-row reads hang off.
    reads: DispatchReads,
}

/// The backend the wave's run-row reads hang off — `list_runs`,
/// `poll_bound` and the `main` head `refresh_head` reads.
enum DispatchReads {
    /// Real GitHub Actions — the operator token `crate::github_token`
    /// resolved.
    GitHub {
        /// The installation-scoped API token.
        token: String,
    },
    /// The mock `stow-build serve` base URL.
    Local {
        /// Base URL — `/tasks` hangs off it.
        base: String,
    },
}

/// One run's state as the driver reads it — `<task_id>` keyed, so the
/// GitHub `workflow_runs` rows (`display_title`, parsed through
/// `parse_run_title`) and the local server's `LocalCiRun` rows fold
/// onto the same record. A run this wave could not have dispatched
/// never produces one.
#[derive(Debug, Clone)]
struct RunState {
    /// The `<task_id>` the run's title carries — the binding key.
    task_id: String,
    workflow_run_id: u64,
    status: String,
    conclusion: Option<String>,
    url: String,
    /// The run's `head_sha` — staleness is judged at fold time against
    /// this poll's `main` head, so a cached row reclassifies the moment
    /// `main` moves. The local CI server always runs the checkout it
    /// serves, so its rows carry an empty sha that is never stale.
    head_sha: String,
    /// GitHub's attempt counter — `rerun-failed-jobs` bumps it, so a
    /// failure observed at `MAX_RUN_ATTEMPTS` is final. The local
    /// server's rows carry a constant 1: it has no runner setup and
    /// never reruns, so the attempt is never consulted there.
    run_attempt: u64,
    /// The run's `created_at` as GitHub served it — the
    /// unresolved-dispatch resolution accepts only runs at or after
    /// the batch's own attempt (minus [`GITHUB_CLOCK_ALLOWANCE`]). The
    /// local server's rows carry none: every run it lists was made by
    /// a dispatch it took, so `None` accepts.
    created_at: Option<time::OffsetDateTime>,
    /// The local backend's task outcome, straight off `GET /tasks` —
    /// GitHub's rows carry none: a GitHub run's task outcome comes from
    /// the attempt's jobs page at classify time.
    error: Option<String>,
}

impl RunState {
    /// A failure on code `main` has since moved past: not this wave's
    /// result, so the node is dispatched again rather than adopted as
    /// failed. A success or a run still in flight is adopted whatever it
    /// ran — the success published, and the in-flight run will.
    fn stale_failure(&self, main_head: &str) -> bool {
        !self.head_sha.is_empty()
            && self.head_sha != main_head
            && self.status == "completed"
            && self.conclusion.as_deref() != Some("success")
    }
}

fn retain_latest_run(
    latest: &mut HashMap<String, RunState>,
    state: RunState,
    tracked_workflow_run_id: Option<u64>,
) {
    if tracked_workflow_run_id.is_some_and(|id| id != state.workflow_run_id) {
        return;
    }
    let replace = latest
        .get(&state.task_id)
        .is_none_or(|current| state.workflow_run_id > current.workflow_run_id);
    if replace {
        latest.insert(state.task_id.clone(), state);
    }
}

/// Entry point — `stow-admin preheat manual`.
pub async fn run(args: ManualArgs, _output: Output) -> stow_types::error::Result<()> {
    if args.in_flight == 0 {
        return Err(stow_error!("--in-flight must be at least 1"));
    }
    if args.crates.is_none() && args.projects.is_none() && args.dirs.is_none() {
        return Err(stow_error!(
            "one of --crates, --projects or --dirs is required"
        ));
    }
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_error!("--rustc-version: {error}"))?;
    let targets = crate::preheat::ci_targets(args.targets.clone())?
        .iter()
        .map(|target| {
            TargetTriple::parse(target.clone())
                .map_err(|error| stow_error!("--targets `{target}`: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let resolved = resolve_sources(&args, &targets, &rustc_version).await?;
    if resolved.requests.is_empty() {
        if !resolved.unresolved_projects.is_empty() {
            return Err(stow_error!(
                "no tasks resolved: {} project(s) failed to resolve:\n{}",
                resolved.unresolved_projects.len(),
                resolved.unresolved_projects.join("\n")
            ));
        }
        render::emit_line("no tasks resolved");
        return Ok(());
    }
    let (mut nodes, edges) = build_graph(resolved.requests)?;

    let policy = DispatchPolicy {
        rustc_version: &rustc_version,
        in_flight: args.in_flight,
    };

    if args.dry_run {
        return dry_run_report(&nodes);
    }

    let dispatch = if let Some(url) = &args.dispatch_url {
        Dispatch {
            interface: CiInterface::local_ci(url.trim_end_matches('/'), ZenwaveTransport),
            reads: DispatchReads::Local {
                base: url.trim_end_matches('/').to_owned(),
            },
        }
    } else {
        let token = crate::github_token().await?;
        Dispatch {
            interface: CiInterface::github(
                stow_types::trusted_builder::REPOSITORY,
                &token,
                ZenwaveTransport,
            ),
            reads: DispatchReads::GitHub { token },
        }
    };

    let base = crate::index_cmd::registry_base()?;
    let http = stow_oci::RegistryHttp::new().await?;
    let repository = cache_repository(&rustc_version);
    let session = base.session(&repository, &http);
    let trust = crate::index_cmd::records_trust().await?;
    let catalog = Index {
        session: &session,
        repository: &repository,
        trust: &trust,
    };
    let adopt_since = args.adopt_since.unwrap_or_else(|| {
        time::OffsetDateTime::now_utc() - time::Duration::hours(ADOPT_SINCE_DEFAULT_HOURS)
    });
    let spellings = nodes
        .iter()
        .map(|(id, node)| (id.clone(), node.request.explicit_spelling))
        .collect();
    let covered = covered_nodes(&catalog, &targets, &rustc_version, &spellings).await?;
    let wave_covered = mark_covered_done(&mut nodes, &covered);
    tracing::info!(
        covered = covered.len(),
        wave_covered,
        "published index coverage"
    );

    let layers = layer_graph(&nodes, &edges, &covered)?;

    let drive = Drive {
        dispatch: &dispatch,
        args: &args,
        catalog: &catalog,
        policy,
        adopt_since,
    };
    let report = drive_layers(&drive, &layers, &mut nodes, &edges).await?;

    finish_report(
        &nodes,
        wave_covered,
        &report.failures,
        &report.blocked,
        &report.reruns,
        &resolved.unresolved_projects,
    )
}

/// The per-wave context every layer drive shares — the dispatch
/// backend, the invocation's args, the index handle, the batching
/// policy and the adoption window.
struct Drive<'a> {
    dispatch: &'a Dispatch,
    args: &'a ManualArgs,
    catalog: &'a Index<'a>,
    policy: DispatchPolicy<'a>,
    adopt_since: time::OffsetDateTime,
}

/// Everything dispatch reads, owned once per invocation: the wave's
/// rustc and the `--in-flight` slot limit — one task is one run and
/// holds one runner slot.
struct DispatchPolicy<'a> {
    rustc_version: &'a WireRustcVersion,
    /// The runner slots in-flight runs may hold in total.
    in_flight: u32,
}

/// Every layer's outcome folded for the finish report: failures as
/// `(task, run url)`, skips as `(task, failed ancestor)`, and the
/// confirmed infrastructure reruns.
#[derive(Default)]
struct WaveReport {
    failures: Vec<(String, String)>,
    blocked: Vec<(String, String)>,
    reruns: Vec<RerunRecord>,
}

/// Drive each non-empty layer in order: mark newly-blocked nodes, run
/// the layer to completion, then publish the index slices its newly
/// done nodes earned. A layer that drove nothing to done — every node
/// failed or was skipped behind a failure — publishes nothing.
async fn drive_layers(
    drive: &Drive<'_>,
    layers: &[Vec<String>],
    nodes: &mut BTreeMap<String, NodeRun>,
    edges: &BTreeMap<String, BTreeSet<String>>,
) -> stow_types::error::Result<WaveReport> {
    let mut report = WaveReport::default();
    for (index, layer) in layers.iter().enumerate() {
        if layer.is_empty() {
            continue;
        }
        tracing::info!(
            layer = index + 1,
            of = layers.len(),
            tasks = layer.len(),
            "manual preheat layer"
        );
        report.blocked.extend(mark_blocked(layer, nodes, edges));
        let done_before = layer
            .iter()
            .filter(|id| nodes.get(*id).expect("layer node").done)
            .count();
        drive_layer(
            drive.dispatch,
            layer,
            LayerPosition {
                index,
                of: layers.len(),
            },
            nodes,
            &mut report.reruns,
            &drive.policy,
            drive.adopt_since,
        )
        .await?;
        let built = layer
            .iter()
            .filter(|id| nodes.get(*id).expect("layer node").done)
            .count()
            - done_before;
        for id in layer {
            let node = nodes.get(id).expect("layer node");
            if node.failed {
                report.failures.push((
                    id.clone(),
                    node.run_url.clone().unwrap_or_else(|| "-".to_owned()),
                ));
            }
        }
        if built > 0 {
            publish_and_wait(
                drive.dispatch,
                drive.args,
                nodes,
                layer,
                drive.catalog,
                drive.policy.rustc_version,
            )
            .await?;
        }
    }
    Ok(report)
}

/// The wave's outcome line plus its failure list — a node still undone
/// failed, or was skipped behind a failed ancestor, a `--projects`
/// repository that never resolved is named too, and the report names
/// all three. Infrastructure reruns are listed as well: runner flakes
/// are reported, not hidden. The run exits non-zero unless every node
/// is done and every project resolved.
///
/// `served` is how many of the wave's nodes the published index already
/// covered — they are `done` without this wave building anything, so the
/// report breaks `done` into built and already-served counts.
fn finish_report(
    nodes: &BTreeMap<String, NodeRun>,
    served: usize,
    failures: &[(String, String)],
    blocked_report: &[(String, String)],
    reruns: &[RerunRecord],
    unresolved_projects: &[String],
) -> stow_types::error::Result<()> {
    let total = nodes.len();
    let done = nodes.values().filter(|node| node.done).count();
    let built = done - served;
    let skipped = nodes
        .values()
        .filter(|node| node.blocked_by.is_some())
        .count();
    let mut report = String::new();
    for (id, url) in failures {
        let _ = writeln!(report, "  FAILED {id} {url}");
    }
    for (id, ancestor) in blocked_report {
        let _ = writeln!(report, "  SKIPPED {id} blocked by {ancestor}");
    }
    for project in unresolved_projects {
        let _ = writeln!(report, "  UNRESOLVED {project}");
    }
    for rerun in reruns {
        let _ = writeln!(
            report,
            "  RERUN {} {} attempt {}: {} / {}",
            rerun.task_id,
            rerun.url,
            rerun.run_attempt,
            rerun.job,
            rerun.step.as_deref().unwrap_or("-")
        );
    }
    let _ = writeln!(
        report,
        "manual preheat: {done}/{total} done ({built} built, {served} already served), \
         {} failed, {skipped} skipped, {} unresolved, {} rerun",
        failures.len(),
        unresolved_projects.len(),
        reruns.len()
    );
    render::emit_line(&report);
    if failures.is_empty() && done == total && unresolved_projects.is_empty() {
        Ok(())
    } else {
        Err(stow_error!(
            "manual preheat incomplete:\n{}",
            report.trim_end()
        ))
    }
}

type ManualTaskGraph = (
    BTreeMap<String, NodeRun>,
    BTreeMap<String, BTreeSet<String>>,
);

/// Fold the wave into the task graph: requests keyed by task id (two
/// sources can name the same identity — dedupe by id), edges to the
/// dep's own task id so the graph keyspace is the queue's.
fn build_graph(requests: Vec<EnqueueRequest>) -> stow_types::error::Result<ManualTaskGraph> {
    let mut nodes: BTreeMap<String, NodeRun> = BTreeMap::new();
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for request in requests {
        // Resolving the carried subgraph is the identity check — it
        // fails on an unresolvable closure before the id is keyed.
        let id = node_task_id(&request)?;
        let deps = request
            .depends_on()?
            .iter()
            .map(dep_task_id)
            .collect::<BTreeSet<_>>();
        edges.entry(id.clone()).or_default().extend(deps);
        nodes.entry(id).or_insert(NodeRun {
            request,
            run_url: None,
            workflow_run_id: None,
            dispatched: false,
            done: false,
            failed: false,
            blocked_by: None,
        });
    }
    Ok((nodes, edges))
}

/// Mark every node the published index already serves done before the
/// first layer is driven: a covered node is never dispatched, never
/// adopted and never lands in a layer — the wave owes it nothing.
/// Returns how many of the wave's own nodes that is.
fn mark_covered_done(nodes: &mut BTreeMap<String, NodeRun>, covered: &BTreeSet<String>) -> usize {
    let mut served = 0;
    for (id, node) in nodes {
        if covered.contains(id) {
            node.done = true;
            served += 1;
        }
    }
    served
}

/// Layer the uncovered graph: depth 0 is a node whose deps the index
/// already serves (or that has none); every other layer waits on the
/// publish the previous layer earned.
fn layer_graph(
    nodes: &BTreeMap<String, NodeRun>,
    edges: &BTreeMap<String, BTreeSet<String>>,
    covered: &BTreeSet<String>,
) -> stow_types::error::Result<Vec<Vec<String>>> {
    let mut layers: Vec<Vec<String>> = Vec::new();
    let mut depth_cache: HashMap<String, usize> = HashMap::new();
    for id in nodes.keys() {
        if covered.contains(id) {
            continue;
        }
        let depth = node_depth(id, edges, covered, &mut depth_cache, &mut BTreeSet::new())?;
        if depth + 1 > layers.len() {
            layers.resize_with(depth + 1, Vec::new);
        }
        layers[depth].push(id.clone());
    }
    Ok(layers)
}

/// The task-graph depth of one node: 0 when every dependency edge lands
/// on the published index (or the node has none), else one above the
/// deepest in-graph dep. `covered` marks ids the index already serves —
/// covered deps add no layer.
fn node_depth(
    id: &str,
    edges: &BTreeMap<String, BTreeSet<String>>,
    covered: &BTreeSet<String>,
    cache: &mut HashMap<String, usize>,
    visiting: &mut BTreeSet<String>,
) -> stow_types::error::Result<usize> {
    if covered.contains(id) {
        return Ok(0);
    }
    if let Some(depth) = cache.get(id) {
        return Ok(*depth);
    }
    if !visiting.insert(id.to_owned()) {
        return Err(stow_error!("dependency cycle reaches {id}"));
    }
    let mut depth = 0;
    for dep in edges.get(id).into_iter().flatten() {
        if covered.contains(dep) || !edges.contains_key(dep) {
            // The index serves it, or the resolve never emitted it —
            // either way the dep adds no layer.
            continue;
        }
        depth = depth.max(1 + node_depth(dep, edges, covered, cache, visiting)?);
    }
    visiting.remove(id);
    cache.insert(id.to_owned(), depth);
    Ok(depth)
}

/// Before a layer dispatches: a node whose dependency failed — or was
/// itself blocked behind a failed ancestor — is marked skipped and
/// never dispatched. Layers are topological, so a dep's fate is final
/// before the layer above it runs. Returns `(node, failed ancestor)`
/// pairs for the report; `blocked_by` always names the failed node,
/// not a skipped intermediate.
fn mark_blocked(
    layer: &[String],
    nodes: &mut BTreeMap<String, NodeRun>,
    edges: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<(String, String)> {
    let mut blocked = Vec::new();
    for id in layer {
        let node = nodes.get(id).expect("layer node");
        if node.done || node.failed || node.blocked_by.is_some() {
            continue;
        }
        let ancestor = edges.get(id).into_iter().flatten().find_map(|dep| {
            let dep_node = nodes.get(dep)?;
            if dep_node.failed {
                Some(dep.clone())
            } else {
                dep_node.blocked_by.clone()
            }
        });
        if let Some(ancestor) = ancestor {
            nodes.get_mut(id).expect("layer node").blocked_by = Some(ancestor.clone());
            blocked.push((id.clone(), ancestor));
        }
    }
    blocked
}

/// One resolve wave's per-source progress: the `done`/`total` count
/// and the wave's start, logged on each delivered result so a running
/// input's log distinguishes completed, failed, and still-in-flight
/// sources instead of going quiet for the whole fetch+resolve span
/// (stow#540). The pool delivers results on the driving thread, so
/// the counters need no sharing.
struct SourceProgress {
    done: usize,
    total: usize,
    started: std::time::Instant,
}

impl SourceProgress {
    fn new(total: usize) -> Self {
        Self {
            done: 0,
            total,
            started: std::time::Instant::now(),
        }
    }

    /// Record one delivered source: log its completion, then fold it
    /// into the wave's accumulators — `Ok` tasks extend `requests`, an
    /// `Err` appends `"{source}: {error}"` to `failures`.
    fn collect(
        &mut self,
        source: impl std::fmt::Display,
        result: Result<Vec<EnqueueRequest>, String>,
        requests: &mut Vec<EnqueueRequest>,
        failures: &mut Vec<String>,
    ) {
        self.done += 1;
        match result {
            Ok(tasks) => {
                tracing::info!(
                    %source,
                    tasks = tasks.len(),
                    done = self.done,
                    total = self.total,
                    elapsed_s = self.started.elapsed().as_secs_f64(),
                    "resolved source"
                );
                requests.extend(tasks);
            }
            Err(error) => {
                tracing::warn!(
                    %source,
                    %error,
                    done = self.done,
                    total = self.total,
                    elapsed_s = self.started.elapsed().as_secs_f64(),
                    "source resolve failed"
                );
                failures.push(format!("{source}: {error}"));
            }
        }
    }
}

/// What the source lanes produced: the resolved task requests, and the
/// `--projects` repositories that failed to resolve. A projects
/// failure is reported and counted rather than aborting the wave — it
/// is named at the finish report and fails the run; a `--crates` or
/// `--dirs` failure still aborts before dispatch.
struct ResolvedSources {
    requests: Vec<EnqueueRequest>,
    /// `"<repo>: <reason>"`, the string `SourceProgress::collect`
    /// builds — only the `--projects` lane feeds this.
    unresolved_projects: Vec<String>,
}

/// Read both inputs into one request list: a crates file resolves each
/// line's newest non-yanked release (or the `@`-pinned one) with the
/// crate lane; a projects file resolves each listed repository's git
/// tree with the projects lane.
async fn resolve_sources(
    args: &ManualArgs,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<ResolvedSources> {
    // Version lookup runs sequentially (crates.io's pace gate); the
    // resolves then fan out on the pool.
    let mut jobs: Vec<(String, semver::Version)> = Vec::new();
    let mut failures = Vec::new();
    if let Some(path) = &args.crates {
        for (name, pinned) in load_crate_list(path).await? {
            match resolve_named_release(name.as_str(), pinned).await {
                Ok(release) => jobs.push((name.as_str().to_owned(), release)),
                Err(error) => failures.push(format!("{name}: {error}")),
            }
        }
    }
    let targets = targets.to_vec();
    let rustc_version = rustc_version.clone();
    let projects = args.projects.clone();
    let source_trees = args.source_trees.clone();
    let dirs = args.dirs.clone();
    let (requests, failures, unresolved_projects) = tokio::task::spawn_blocking(move || {
        let pool = crate::resolve::ResolvePool::new(&rustc_version)?;
        let mut requests = Vec::new();
        let mut unresolved_projects = Vec::new();
        if !jobs.is_empty() {
            let mut progress = SourceProgress::new(jobs.len());
            pool.run(
                &jobs,
                |resolver, runtime, (name, version)| {
                    crate::resolve::resolve_crate(
                        resolver,
                        runtime,
                        name,
                        version,
                        &targets,
                        &rustc_version,
                        0,
                    )
                    .map(|source| {
                        source
                            .targets
                            .into_iter()
                            .flat_map(|(_target, tasks)| tasks)
                            .collect::<Vec<EnqueueRequest>>()
                    })
                },
                |_, (name, version), result| {
                    progress.collect(
                        format_args!("{name}@{version}"),
                        result,
                        &mut requests,
                        &mut failures,
                    );
                },
            )?;
        }
        if let Some(path) = &projects {
            resolve_projects_lane(
                &pool,
                path,
                source_trees.as_ref(),
                &targets,
                &rustc_version,
                &mut requests,
                &mut unresolved_projects,
            )?;
        }
        if let Some(dirs) = &dirs {
            let mut progress = SourceProgress::new(dirs.len());
            pool.run(
                dirs,
                |resolver, _runtime, dir| {
                    crate::projects::resolve_project_dir(resolver, dir, &targets, &rustc_version)
                },
                |_, dir, result| {
                    progress.collect(dir.display(), result, &mut requests, &mut failures);
                },
            )?;
        }
        Ok::<_, stow_types::error::Error>((requests, failures, unresolved_projects))
    })
    .await
    .expect("resolve pool panicked")?;
    if !failures.is_empty() {
        return Err(stow_error!(
            "resolve failed for {} source(s):\n{}",
            failures.len(),
            failures.join("\n")
        ));
    }
    Ok(ResolvedSources {
        requests,
        unresolved_projects,
    })
}

/// The `--projects` lane inside `resolve_sources`: load the file and
/// the declared source trees, then fan the repositories over the pool.
/// A repository that fails to resolve lands in `unresolved_projects`
/// — reported and counted at the finish report (stow#572) — rather
/// than aborting the wave like a `--crates` or `--dirs` failure.
fn resolve_projects_lane(
    pool: &crate::resolve::ResolvePool,
    projects: &Path,
    source_trees: Option<&PathBuf>,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    requests: &mut Vec<EnqueueRequest>,
    unresolved_projects: &mut Vec<String>,
) -> stow_types::error::Result<()> {
    let repos = tokio::runtime::Handle::current()
        .block_on(crate::projects::load_projects_file(projects))?;
    let trees = crate::source_trees::load_optional_source_trees(source_trees, &repos)?;
    let mut progress = SourceProgress::new(repos.len());
    pool.run(
        &repos,
        |resolver, _runtime, repo| {
            crate::projects::resolve_repository(
                resolver,
                repo,
                targets,
                rustc_version,
                trees.as_ref().and_then(|trees| trees.get(repo)),
            )
        },
        |_, repo, result| {
            progress.collect(repo, result, requests, unresolved_projects);
        },
    )?;
    Ok(())
}

/// The crate list's version semantics — `name@version` names that
/// non-yanked release exactly, a bare name takes the newest non-yanked.
async fn resolve_named_release(
    name: &str,
    pinned: Option<CrateVersion>,
) -> stow_types::error::Result<semver::Version> {
    let releases = crate::crates_io::index_releases(name).await?;
    if let Some(pinned) = pinned {
        let wanted = pinned.to_string();
        return if releases
            .iter()
            .any(|release| release.version == *pinned.as_semver() && !release.yanked)
        {
            Ok(pinned.as_semver().clone())
        } else {
            Err(stow_error!("crates.io lists no non-yanked {name} {wanted}"))
        };
    }
    let latest = crate::crates_io::latest_version(&releases)
        .ok_or_else(|| stow_error!("crates.io lists no non-yanked release of {name}"))?;
    semver::Version::parse(&latest).map_err(|error| stow_error!("{name} version {latest}: {error}"))
}

/// Parse a crate list file: `name` or `name@version` per line, `#`
/// comments and blanks ignored.
async fn load_crate_list(
    path: &Path,
) -> stow_types::error::Result<Vec<(CrateName, Option<CrateVersion>)>> {
    let raw = tokio::fs::read(path)
        .await
        .map_err(|error| stow_error!("read {}: {error}", path.display()))?;
    let text = String::from_utf8(raw)
        .map_err(|error| stow_error!("{} is not UTF-8: {error}", path.display()))?;
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let (name, version) = crate::coverage::parse_crate_spec(line)
            .map_err(|error| stow_error!("{}:{}: {error}", path.display(), index + 1))?;
        entries.push((name, version));
    }
    if entries.is_empty() {
        return Err(stow_error!("{} lists no crates", path.display()));
    }
    Ok(entries)
}

/// A request's own task id — the `run-name` every dispatched run
/// carries. Deriving it resolves the carried subgraph (stow#588).
fn node_task_id(request: &EnqueueRequest) -> stow_types::error::Result<String> {
    request.task_id()
}

/// The dep's own task id — a dependency edge points at the dep's
/// identity tuple, exactly as the scheduler computes it.
fn dep_task_id(dep: &EnqueueDependency) -> String {
    dep.task_id()
}

/// The runner-family host triple `target`'s host-side nodes mint on.
fn host_triple(target: &TargetTriple) -> String {
    stow_types::api::runner_family(target.as_str()).map_or_else(
        || target.as_str().to_owned(),
        |family| family.host_triple().to_owned(),
    )
}

/// The set of task ids the published slices already serve — semantic
/// identity coverage per the queue gate's shape rules: a host-side node
/// needs both invocation spellings' linked rows; a target-side node the
/// linked+unlinked pair of its own spelling. `pub` for the request
/// lane, which reports its `cached` roots off this set.
pub async fn covered_nodes(
    index: &Index<'_>,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    spellings: &BTreeMap<String, stow_types::public_cache::ExplicitSpelling>,
) -> stow_types::error::Result<BTreeSet<String>> {
    let mut covered = BTreeSet::new();
    // Slice pulls are reads — fan them out under the bounded
    // concurrency every index pull in this crate shares.
    let rows_per_target: Vec<Option<Vec<ArtifactIndexRow>>> = futures_util::stream::iter(
        targets
            .iter()
            .map(|target| published_slice_rows(index, target, rustc_version)),
    )
    .buffered(SLICE_PULL_CONCURRENCY)
    .try_collect()
    .await?;
    for (target, rows) in targets.iter().zip(rows_per_target) {
        let Some(rows) = rows else { continue };
        covered.extend(covered_slice_nodes(
            &rows,
            target,
            rustc_version,
            spellings,
        )?);
    }
    Ok(covered)
}

fn covered_slice_nodes(
    rows: &[ArtifactIndexRow],
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
    spellings: &BTreeMap<String, stow_types::public_cache::ExplicitSpelling>,
) -> stow_types::error::Result<BTreeSet<String>> {
    let mut shapes = HashMap::<_, BTreeSet<_>>::new();
    for row in rows {
        let shape = row.unit_shape;
        let dependency_identity = &row.dependency_identity;
        let host_side = shape.side == stow_types::public_cache::UnitSide::Host;
        if host_side && host_triple(target) != target.as_str() {
            return Err(stow_error!("host row reported in non-host slice {target}"));
        }
        let identity = TaskNodeIdentity {
            crate_name: row.crate_name.clone(),
            version: row.version.clone(),
            features_json: row.features_json.clone(),
            target: target.clone(),
            rustc_version: rustc_version.clone(),
            host_side,
        };
        shapes
            .entry((identity, dependency_identity.clone()))
            .or_default()
            .insert(shape);
    }
    let invocation = if host_triple(target) == target.as_str() {
        UnitInvocation::Native
    } else {
        UnitInvocation::Target
    };
    Ok(shapes
        .into_iter()
        .filter(|((identity, context), served)| {
            // The flag the node's own request carries — rows for nodes
            // nothing asked about answer the historical two-shape rule.
            let spelling = spellings
                .get(&identity.task_id(context))
                .copied()
                .unwrap_or_default();
            required_unit_shapes(identity.host_side, invocation, spelling)
                .iter()
                .all(|shape| served.contains(shape))
        })
        .map(|((identity, context), _)| identity.task_id(&context))
        .collect())
}

pub async fn contextual_coverage(
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    spellings: &BTreeMap<String, stow_types::public_cache::ExplicitSpelling>,
) -> stow_types::error::Result<BTreeSet<String>> {
    let base = crate::index_cmd::registry_base()?;
    let http = stow_oci::RegistryHttp::new().await?;
    let repository = cache_repository(rustc_version);
    let session = base.session(&repository, &http);
    let trust = crate::index_cmd::records_trust().await?;
    covered_nodes(
        &Index {
            session: &session,
            repository: &repository,
            trust: &trust,
        },
        targets,
        rustc_version,
        spellings,
    )
    .await
}

/// The three handles the index-slice pulls share — `pub` so the
/// request lane pulls the same verified slices.
pub struct Index<'a> {
    pub session: &'a stow_oci::RegistrySession,
    pub repository: &'a CacheRepository,
    pub trust: &'a stow_oci::verify::Trust,
}

/// Pull and verify the published `index.<target>.<rustc>` slice —
/// `None` when the tag does not exist (a fresh registry serves an empty
/// catalog, not an error).
pub async fn published_slice_rows(
    index: &Index<'_>,
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<Option<Vec<ArtifactIndexRow>>> {
    let tag = index_tag(target.as_str(), rustc_version.as_str());
    let reference = index.session.reference(&tag)?;
    let (bytes, manifest_digest) = match index.session.pull_manifest(&reference).await {
        Ok(pair) => pair,
        Err(error) if error.is_not_found() => return Ok(None),
        Err(error) => return Err(stow_error!("pull index {reference}: {error}")),
    };
    let manifest: OciImageManifest = serde_json::from_slice(&bytes)
        .map_err(|error| stow_error!("parse index manifest {reference}: {error}"))?;
    let [layer] = manifest.layers.as_slice() else {
        return Err(stow_error!(
            "index manifest {reference} carries {} layers, expected exactly one",
            manifest.layers.len()
        ));
    };
    if layer.media_type != STOW_INDEX_MEDIA_TYPE {
        return Err(stow_error!(
            "index manifest {reference} layer is {}, expected {STOW_INDEX_MEDIA_TYPE}",
            layer.media_type
        ));
    }
    let blob = stow_oci::pull_blob_verified(index.session, layer).await?;
    let materials =
        stow_oci::pull_signature_materials(index.session, &reference, &manifest_digest).await?;
    stow_oci::verify::verify_materials(
        index.trust,
        &index.repository.reference(&tag),
        &manifest_digest,
        &materials,
        INDEX_CERTIFICATE_IDENTITY,
    )?;
    let index = crate::index_cmd::decode_published_slice(&reference, rustc_version, &blob)?;
    if index.header.target.as_str() != target.as_str()
        || index.header.rustc_version.as_str() != rustc_version.as_str()
    {
        return Err(stow_error!(
            "index slice {tag} was published for {}@{}",
            index.header.target.as_str(),
            index.header.rustc_version.as_str()
        ));
    }
    Ok(Some(index.rows))
}

/// `--dry-run`: encode every wave node's task payload exactly as a
/// drive would send it and report each one's size and fill of the
/// dispatch input cap (stow#588).
fn dry_run_report(nodes: &BTreeMap<String, NodeRun>) -> stow_types::error::Result<()> {
    let mut out = format!("dry run: {} node(s), none dispatched", nodes.len());
    let mut sizes = Vec::with_capacity(nodes.len());
    for (index, (id, node)) in nodes.iter().enumerate() {
        let encoded = serde_json::to_string(&task_payload(id, &node.request))
            .map_err(|error| stow_error!("encode {id}: {error}"))?;
        if encoded.len() > stow_types::api::DISPATCH_INPUT_LIMIT {
            return Err(stow_error!(
                "task {id} encodes to {} bytes — over the {}-char dispatch input cap",
                encoded.len(),
                stow_types::api::DISPATCH_INPUT_LIMIT
            ));
        }
        sizes.push(encoded.len());
        let _ = writeln!(
            out,
            "  task {index}: {} bytes ({}% of the {}-char input cap)",
            encoded.len(),
            encoded.len() * 100 / stow_types::api::DISPATCH_INPUT_LIMIT,
            stow_types::api::DISPATCH_INPUT_LIMIT,
        );
    }
    sizes.sort_unstable();
    if let Some(&max) = sizes.last() {
        let p99 = sizes
            .get(sizes.len().saturating_mul(99).saturating_add(99) / 100 - 1)
            .copied()
            .unwrap_or(0);
        let _ = writeln!(
            out,
            "  encoded task input: max {max} bytes, p99 {p99} bytes"
        );
    }
    render::emit_line(&out);
    Ok(())
}

/// The dispatch's payload — `BuildTaskPayload` exactly as the scheduler
/// builds it, `attempt` 1 (the manual wave never re-queues in place).
fn task_payload(task_id: &str, request: &EnqueueRequest) -> BuildTaskPayload {
    BuildTaskPayload {
        task_id: task_id.to_owned(),
        attempt: 1,
        crate_name: request.crate_name.clone(),
        version: request.version.clone(),
        features_json: request.features_json.clone(),
        target: request.target.clone(),
        rustc_version: request.rustc_version.clone(),
        preserve_lockfile: request.preserve_lockfile,
        host_side: request.host_side,
        explicit_spelling: request.explicit_spelling,
        // The resolver emitted this node's whole transitive dependency
        // closure on the request — covered nodes included — so the
        // dispatched payload reproduces the context the folded graph
        // already pruned out of the wave (stow#588).
        dependency_subgraph: request.dependency_subgraph.clone(),
    }
}

/// What one dispatch send settled — the driver's dispatch pass reads
/// this to decide whether the pass continues.
enum DispatchAnswer {
    /// The run id came back — the batch is bound.
    Bound,
    /// The answer was ambiguous: the write may have landed, so the
    /// batch holds the attempt and waits for the resolution listing.
    Ambiguous(WriteFailure),
    /// GitHub's rate limit answered first — nothing happened and the
    /// batch stays unsent; the hint is the answer's `Retry-After`.
    RateLimited(WriteFailure),
}

/// Dispatch one task: a confirmed send binds it to the run id
/// returned; an ambiguous answer leaves it [`BoundRun::unresolved`]
/// with its node held; a rate limit leaves it unsent; a refusal is
/// the error it always was.
async fn dispatch_task(
    dispatch: &Dispatch,
    task_id: String,
    encoded: String,
    wave: &mut Wave<'_>,
) -> stow_types::error::Result<DispatchAnswer> {
    // Both clocks ride every ambiguous attempt: the wall clock bounds
    // the resolution listing, the monotonic instant the re-send grace.
    let wall = time::OffsetDateTime::now_utc();
    let instant = tokio::time::Instant::now();
    let mut bound = BoundRun {
        task_id: task_id.clone(),
        workflow_run_id: None,
        run_url: None,
        etag: None,
        latest: None,
        observed: false,
        unresolved: None,
        pending_rerun: None,
        dispatched_at: None,
    };
    match dispatch.send(&encoded).await {
        Ok(run_id) => {
            bound.workflow_run_id = Some(run_id);
            bound.dispatched_at = Some(std::time::Instant::now());
            wave.nodes.get_mut(&task_id).expect("task node").dispatched = true;
            wave.runs.insert(task_id, bound);
            Ok(DispatchAnswer::Bound)
        }
        Err(failure @ WriteFailure::Refused(_)) => Err(failure.into()),
        Err(failure) => {
            if matches!(failure, WriteFailure::Ambiguous(_)) {
                bound.unresolved = Some(UnansweredDispatch { wall, instant });
                wave.nodes.get_mut(&task_id).expect("task node").dispatched = true;
                wave.runs.insert(task_id, bound);
                return Ok(DispatchAnswer::Ambiguous(failure));
            }
            Ok(DispatchAnswer::RateLimited(failure))
        }
    }
}

/// Fold one observed run state that needs no task classification —
/// shared by the one-time adoption fold and every bound-run poll for
/// rows that are not completed failures on current code. A stale
/// failure drops the run's binding so its node dispatches afresh; an
/// in-flight row binds; a completed success marks the node done and
/// frees the run's slot.
fn fold_simple(task_id: &str, state: &RunState, wave: &mut Wave<'_>, main_head: &str) {
    if state.stale_failure(main_head) {
        // The run this task was tracking ended as a failure of older
        // code: release the node still bound to it — it dispatches
        // afresh. The match is the bound run id, so a node a newer run
        // claimed is untouched.
        if let Some(run) = wave.runs.get(task_id) {
            release_task(run, state.workflow_run_id, wave.nodes);
        }
        wave.runs.remove(task_id);
        return;
    }
    let Some(run) = wave.runs.get_mut(task_id) else {
        return;
    };
    bind_run(run, state, wave.nodes);
    if state.status == "completed" && state.conclusion.as_deref() == Some("success") {
        let node = wave.nodes.get_mut(task_id).expect("a bound run's task");
        if node.workflow_run_id == Some(state.workflow_run_id) {
            node.done = true;
            wave.open.remove(task_id);
        }
        // The run settled its task — its slot frees.
        wave.runs.remove(task_id);
    }
}

/// Bind a task's node to `state`'s run without judging the outcome —
/// a bound run settles an ambiguous dispatch, and `latest` records
/// the freshest row so a 304 refold sees it rather than a stale
/// predecessor. A node a newer run already claimed keeps its binding.
fn bind_run(run: &mut BoundRun, state: &RunState, nodes: &mut BTreeMap<String, NodeRun>) {
    run.run_url = Some(state.url.clone());
    run.workflow_run_id = Some(state.workflow_run_id);
    run.unresolved = None;
    run.latest = Some(state.clone());
    run.observed = true;
    let node = nodes.get_mut(&run.task_id).expect("a bound run's task");
    if node
        .workflow_run_id
        .is_none_or(|id| id == state.workflow_run_id)
    {
        node.run_url = Some(state.url.clone());
        node.workflow_run_id = Some(state.workflow_run_id);
        node.dispatched = true;
    }
}

/// Release a run's node it can no longer answer for — a stale
/// failure's fold or an expired grace: the node still bound to the
/// run returns to unsent.
fn release_task(run: &BoundRun, run_id: u64, nodes: &mut BTreeMap<String, NodeRun>) {
    let node = nodes.get_mut(&run.task_id).expect("a bound run's task");
    if node.workflow_run_id == Some(run_id) {
        node.run_url = None;
        node.workflow_run_id = None;
        node.dispatched = false;
    }
}

/// One infrastructure rerun for the finish report: the run, the job
/// and step it failed in, and the attempt the rerun runs as — the
/// failed attempt's `run_attempt` + 1.
struct RerunRecord {
    task_id: String,
    url: String,
    job: String,
    step: Option<String>,
    run_attempt: u64,
}

/// One settled run's task fold: apply the outcome to its node — a
/// success marks done, a verdict fails, and an infrastructure or
/// concluded task earns a rerun slot — unless the run is at
/// `MAX_RUN_ATTEMPTS`, where it fails with the rest. Returns the task
/// that earned the rerun for the ask and its record.
fn fold_run_outcome(
    outcome: &TaskOutcome,
    run: &BoundRun,
    run_id: u64,
    maxed: bool,
    nodes: &mut BTreeMap<String, NodeRun>,
    open: &mut BTreeSet<String>,
) -> Option<RerunTask> {
    let node = nodes.get_mut(&run.task_id)?;
    if node.workflow_run_id != Some(run_id) {
        return None;
    }
    match outcome {
        TaskOutcome::Succeeded => {
            node.done = true;
            open.remove(&run.task_id);
            None
        }
        TaskOutcome::Unsettled => None,
        TaskOutcome::Failed(failure) => match failure {
            crate::runs::TaskFailure::Run(RunFailure::Infrastructure { job, step, .. })
                if !maxed =>
            {
                Some(RerunTask {
                    task_id: run.task_id.clone(),
                    job: job.clone(),
                    step: step.clone(),
                })
            }
            crate::runs::TaskFailure::Concluded { job, conclusion } if !maxed => Some(RerunTask {
                task_id: run.task_id.clone(),
                job: job.clone(),
                step: Some(conclusion.clone()),
            }),
            _ => {
                node.failed = true;
                open.remove(&run.task_id);
                None
            }
        },
    }
}

/// The rerun write's answer applied: confirmed records every earning
/// leg and drops the batch's cached row so the next poll reads the
/// rerun's own state; ambiguous keeps the ask as `pending_rerun`; a
/// rate limit asks nothing — the row classifies again once the gate
/// reopens; a refusal is the error it always was.
fn apply_rerun_answer(
    task_id: &str,
    state: &RunState,
    earner: RerunTask,
    answer: Result<(), WriteFailure>,
    wave: &mut Wave<'_>,
) -> stow_types::error::Result<()> {
    match answer {
        Ok(()) => {
            wave.gate.confirmed();
            wave.reruns.push(RerunRecord {
                task_id: earner.task_id,
                url: state.url.clone(),
                job: earner.job,
                step: earner.step,
                run_attempt: state.run_attempt + 1,
            });
            let run = wave.runs.get_mut(task_id).expect("rerun run");
            run.etag = None;
            run.latest = None;
            Ok(())
        }
        Err(failure @ WriteFailure::Refused(_)) => Err(failure.into()),
        Err(failure) => {
            if matches!(failure, WriteFailure::Ambiguous(_)) {
                wave.runs.get_mut(task_id).expect("rerun run").pending_rerun = Some(PendingRerun {
                    attempt: state.run_attempt,
                    asked_at: tokio::time::Instant::now(),
                    task: earner,
                });
            }
            wave.gate.hold(&failure)
        }
    }
}

/// The GitHub arm of a completed non-success fold: the attempt's
/// jobs classify the task with `classify_page` — a settled run folds
/// its task, an unsettled one defers until the next poll. An
/// infrastructure task earns `rerun-failed-jobs` on the run —
/// bounded by `MAX_RUN_ATTEMPTS`.
async fn classify_github_run(
    token: &str,
    state: &RunState,
    wave: &mut Wave<'_>,
) -> stow_types::error::Result<()> {
    let jobs = crate::runs::fetch_attempt_jobs(
        Some(token),
        crate::github::API_BASE,
        state.workflow_run_id,
        state.run_attempt,
        None,
        Backoff::outage,
    )
    .await?;
    let outcome = classify_page(
        &jobs,
        state.conclusion.as_deref().unwrap_or(""),
        time::OffsetDateTime::now_utc(),
    )
    .map_err(|error| stow_error!("run {}: {error}", state.workflow_run_id))?;
    if matches!(outcome, TaskOutcome::Unsettled) {
        // The jobs page was still settling — bind and read again next
        // poll; the run's own row may 304 forever, so `latest` is what
        // re-enters here.
        let run = wave.runs.get_mut(&state.task_id).expect("classified run");
        bind_run(run, state, wave.nodes);
        return Ok(());
    }
    let maxed = state.run_attempt >= MAX_RUN_ATTEMPTS;
    let earner = {
        let run = wave.runs.get_mut(&state.task_id).expect("classified run");
        bind_run(run, state, wave.nodes);
        fold_run_outcome(
            &outcome,
            run,
            state.workflow_run_id,
            maxed,
            wave.nodes,
            wave.open,
        )
    };
    let Some(earner) = earner else {
        // The task settled — the run's slot frees.
        wave.runs.remove(&state.task_id);
        return Ok(());
    };
    tracing::warn!(
        run = state.workflow_run_id,
        attempt = state.run_attempt + 1,
        "infrastructure failure; rerunning the run's failed jobs"
    );
    let answer = crate::github::post_empty(
        token,
        &format!("actions/runs/{}/rerun-failed-jobs", state.workflow_run_id),
        &serde_json::json!({}),
    )
    .await;
    apply_rerun_answer(&state.task_id, state, earner, answer, wave)
}

/// The local arm of a completed-run fold: the run's own status and
/// conclusion settle its task — `success` marks its node done and
/// every other settled answer fails it, final, for the local server
/// has no runner infrastructure to retry.
fn fold_local_task(state: &RunState, wave: &mut Wave<'_>) {
    {
        let Some(run) = wave.runs.get_mut(&state.task_id) else {
            return;
        };
        bind_run(run, state, wave.nodes);
    }
    let Some(node) = wave.nodes.get_mut(&state.task_id) else {
        wave.runs.remove(&state.task_id);
        return;
    };
    if node.workflow_run_id == Some(state.workflow_run_id) {
        match (state.status.as_str(), state.conclusion.as_deref()) {
            ("completed", Some("success")) => {
                node.done = true;
                wave.open.remove(&state.task_id);
            }
            ("completed", _) => {
                if let Some(error) = &state.error {
                    tracing::warn!(task = %state.task_id, %error, "task failed");
                }
                node.failed = true;
                wave.open.remove(&state.task_id);
            }
            _ => {
                // Still in flight — the run stays bound.
                return;
            }
        }
    }
    // The run is completed — its slot frees.
    wave.runs.remove(&state.task_id);
}

/// The async half `fold_simple` cannot do: a completed non-success run
/// on current `main` is classified through the backend first — GitHub
/// reads the attempt's jobs and classifies each leg, an infrastructure
/// leg earning a rerun of the run's failed jobs instead of the node's
/// verdict; the local server's leg rows carry the answer and every
/// failure is final. Everything else — in-flight runs, successes,
/// stale failures and runs of other batches — folds untouched.
///
/// A batch whose rerun write never answered carries `pending_rerun`:
/// a row showing a later `run_attempt`, or one no longer `completed`,
/// is the answer — the rerun was accepted, so the records the success
/// path would have pushed land and the row folds as usual. The same
/// completed attempt inside `RUN_GRACE_MINUTES` is no answer yet;
/// past the grace the pending record drops and the row classifies
/// again, resending the ask.
async fn classify_and_fold(
    dispatch: &Dispatch,
    state: RunState,
    wave: &mut Wave<'_>,
    main_head: &str,
) -> stow_types::error::Result<()> {
    match wave
        .runs
        .get(&state.task_id)
        .and_then(|run| run.pending_rerun.as_ref())
    {
        Some(pending) if state.run_attempt > pending.attempt || state.status != "completed" => {
            let pending = wave
                .runs
                .get_mut(&state.task_id)
                .expect("pending run")
                .pending_rerun
                .take()
                .expect("pending rerun");
            let task = pending.task;
            wave.reruns.push(RerunRecord {
                task_id: task.task_id,
                url: state.url.clone(),
                job: task.job,
                step: task.step,
                run_attempt: pending.attempt + 1,
            });
        }
        Some(pending)
            if pending.asked_at.elapsed()
                < std::time::Duration::from_secs(60 * RUN_GRACE_MINUTES) =>
        {
            // The same completed attempt inside the grace — the
            // write's answer is still out; classify nothing until it
            // resolves. The row still binds — it is the bound run's
            // freshest state, and a 304 refolds it rather than a stale
            // predecessor.
            let run = wave.runs.get_mut(&state.task_id).expect("pending run");
            bind_run(run, &state, wave.nodes);
            return Ok(());
        }
        Some(_) => {
            // The same completed attempt past the grace — the write
            // did not happen as far as the run can tell: drop the
            // pending record and classify again below.
            wave.runs
                .get_mut(&state.task_id)
                .expect("pending run")
                .pending_rerun = None;
        }
        None => {}
    }
    let failed = state.status == "completed" && state.conclusion.as_deref() != Some("success");
    if !failed || state.stale_failure(main_head) || !wave.runs.contains_key(&state.task_id) {
        fold_simple(&state.task_id, &state, wave, main_head);
        return Ok(());
    }
    // The run row lags a rerun request by a beat: a failure row for an
    // attempt a rerun already superseded is not a new verdict — wait
    // for the rerun's own state rather than classifying it again.
    if wave
        .reruns
        .iter()
        .any(|rerun| rerun.url == state.url && rerun.run_attempt > state.run_attempt)
    {
        return Ok(());
    }
    // Classification may ask for a rerun — a write, so it waits out a
    // closed gate exactly like a dispatch does.
    if !wave.gate.open() {
        let run = wave.runs.get_mut(&state.task_id).expect("classified run");
        bind_run(run, &state, wave.nodes);
        return Ok(());
    }
    match &dispatch.reads {
        DispatchReads::Local { .. } => fold_local_task(&state, wave),
        DispatchReads::GitHub { token } => classify_github_run(token, &state, wave).await?,
    }
    Ok(())
}

/// One tick's partition of a layer for the progress line: `done`,
/// `failed`, `skipped`, `dispatched` and `remaining` sum to `total`,
/// and `running` breaks out the dispatched tasks whose bound run
/// GitHub still reports `in_progress`.
#[derive(Default, Debug, PartialEq, Eq)]
struct LayerProgress {
    total: usize,
    done: usize,
    failed: usize,
    skipped: usize,
    dispatched: usize,
    running: usize,
    remaining: usize,
}

/// Partition `layer`'s nodes into the progress counts — pure: the wave
/// state the driver already holds answers every count, and `open` is
/// never consulted since its unresolved-unblocked subset is exactly
/// `remaining` plus the in-flight part of `dispatched`. A settled
/// task keeps `dispatched` set (the folds never clear it), so the
/// `dispatched` arm must re-test `done`/`failed`, and `skipped` stands
/// apart because blocked nodes are dropped before dispatch. The
/// partition is structural — each node lands in one bucket — and the
/// `debug_assert!` keeps the invariant stated.
fn layer_progress(
    layer: &[String],
    nodes: &BTreeMap<String, NodeRun>,
    runs: &HashMap<String, BoundRun>,
) -> LayerProgress {
    let running: BTreeSet<u64> = runs
        .values()
        .filter(|run| {
            run.latest
                .as_ref()
                .is_some_and(|state| state.status == "in_progress")
        })
        .filter_map(|run| run.workflow_run_id)
        .collect();
    let mut progress = LayerProgress {
        total: layer.len(),
        ..LayerProgress::default()
    };
    for id in layer {
        let node = nodes.get(id).expect("layer node");
        if node.done {
            progress.done += 1;
        } else if node.failed {
            progress.failed += 1;
        } else if node.blocked_by.is_some() {
            progress.skipped += 1;
        } else if node.dispatched {
            progress.dispatched += 1;
            if node
                .workflow_run_id
                .is_some_and(|run_id| running.contains(&run_id))
            {
                progress.running += 1;
            }
        } else {
            progress.remaining += 1;
        }
    }
    debug_assert!(
        progress.done
            + progress.failed
            + progress.skipped
            + progress.dispatched
            + progress.remaining
            == progress.total,
        "the progress counts partition the layer"
    );
    progress
}

/// A layer's position among the wave's layers — `index` is 0-based
/// (the lines log `index + 1`), `of` the layer count; the same pair
/// `drive_layers` logs on its `layer` line.
#[derive(Clone, Copy)]
struct LayerPosition {
    index: usize,
    of: usize,
}

/// Emit the layer progress line on the driver's diagnostic stream —
/// `position` places the layer exactly as `drive_layers`' own `layer`
/// line does.
fn log_layer_progress(position: LayerPosition, progress: &LayerProgress) {
    tracing::info!(
        layer = position.index + 1,
        of = position.of,
        total = progress.total,
        done = progress.done,
        failed = progress.failed,
        skipped = progress.skipped,
        dispatched = progress.dispatched,
        running = progress.running,
        remaining = progress.remaining,
        "layer progress"
    );
}

/// Drive one layer to completion: adopt once — every run in the closed
/// `[adopt_since, now]` window whose title names an open node — dispatch
/// the rest bounded by `in_flight`, then poll only the run ids the wave
/// is bound to until every node resolves. Nodes whose runs never
/// materialize inside the grace window surface as an error — GitHub
/// accepted the dispatch and dropped it.
///
/// A dispatch whose answer was ambiguous (`unresolved`) is settled by a
/// runs listing over the attempt's window once per poll: a qualifying
/// run binds the node, and an attempt that outlives `RUN_GRACE_MINUTES`
/// with no run found returns to unsent for a fresh dispatch. Every
/// write — dispatch or rerun — shares `gate`: an answer that settled
/// nothing pauses sends for the backoff's wait while polling and
/// resolution run on. `position` is the layer's place among the
/// wave's layers, for the per-minute `layer progress` line.
async fn drive_layer(
    dispatch: &Dispatch,
    layer: &[String],
    position: LayerPosition,
    nodes: &mut BTreeMap<String, NodeRun>,
    reruns: &mut Vec<RerunRecord>,
    policy: &DispatchPolicy<'_>,
    adopt_since: time::OffsetDateTime,
) -> stow_types::error::Result<()> {
    let mut open: BTreeSet<String> = layer
        .iter()
        .filter(|id| {
            let node = nodes.get(*id).expect("layer node");
            !node.done && !node.failed && node.blocked_by.is_none()
        })
        .cloned()
        .collect();
    // Adoption happens exactly once per layer: the whole closed window
    // `[adopt_since, now]` enumerates completely (past the runs-listing
    // cap, subdividing as needed), so a run the wave tracks cannot drown
    // under newer unrelated history. Runs dispatched from here on are
    // bound by the id the dispatch response returns, and polls read only
    // those ids — later listings are only the narrow unresolved-dispatch
    // resolutions, each restricted to the batches still waiting on an
    // answer.
    let mut head_cache: Option<HeadCache> = None;
    let mut gate = WriteGate::new();
    let mut runs = HashMap::new();
    let mut wave = Wave {
        nodes,
        open: &mut open,
        runs: &mut runs,
        reruns,
        gate: &mut gate,
    };
    let main_head = dispatch.refresh_head(&mut head_cache).await?;
    adopt_runs(
        dispatch,
        &mut wave,
        adopt_since,
        policy.rustc_version,
        &main_head,
    )
    .await?;
    let mut last_progress = tokio::time::Instant::now();
    loop {
        // `main`'s head is read once per poll — usually a free 304 —
        // and every row's staleness is judged against it.
        let main_head = dispatch.refresh_head(&mut head_cache).await?;
        // Settle the sends GitHub may never have heard: one listing
        // over the window from the earliest unresolved attempt to now.
        resolve_unanswered(dispatch, &mut wave, &main_head, policy.rustc_version).await?;
        for outcome in dispatch.poll_bound(wave.runs, policy.rustc_version).await? {
            fold_bound_outcome(dispatch, outcome, &mut wave, &main_head).await?;
        }
        dispatch_open(dispatch, &mut wave, policy).await?;
        if wave.open.is_empty() {
            // The final line — the last state is never a tick stale.
            log_layer_progress(position, &layer_progress(layer, wave.nodes, wave.runs));
            return Ok(());
        }
        if last_progress.elapsed() >= std::time::Duration::from_secs(LAYER_PROGRESS_SECONDS) {
            log_layer_progress(position, &layer_progress(layer, wave.nodes, wave.runs));
            last_progress = tokio::time::Instant::now();
        }
        let overdue: Vec<String> = wave
            .runs
            .values()
            .filter(|run| dispatch_overdue(run))
            .map(|run| run.task_id.clone())
            .collect();
        if !overdue.is_empty() {
            return Err(stow_error!(
                "dispatched runs never appeared on the runs list: {}",
                overdue.join(", ")
            ));
        }
        tokio::time::sleep(std::time::Duration::from_secs(RUN_POLL_SECONDS)).await;
    }
}

/// Fold one bound-run poll answer: a fresh row carries its validator
/// onto the batch before the fold; `Unmodified` refolds the batch's
/// cached row — a `main` head that moved this poll can still stale it;
/// `Pending` is an id that has not materialized or a row whose title
/// has not rendered.
async fn fold_bound_outcome(
    dispatch: &Dispatch,
    outcome: BoundPoll,
    wave: &mut Wave<'_>,
    main_head: &str,
) -> stow_types::error::Result<()> {
    match outcome {
        BoundPoll::State {
            task_id,
            state,
            etag,
        } => {
            if let Some(run) = wave.runs.get_mut(&task_id) {
                run.etag = etag;
            }
            classify_and_fold(dispatch, state, wave, main_head).await?;
        }
        BoundPoll::Unmodified(task_id) => {
            let cached = wave.runs.get(&task_id).and_then(|run| run.latest.clone());
            if let Some(state) = cached {
                classify_and_fold(dispatch, state, wave, main_head).await?;
            }
        }
        BoundPoll::Pending => {}
    }
    Ok(())
}

/// One iteration's dispatch pass, gated by the wave's write gate:
/// send each open undispatched node's task serially — mutating calls
/// are what GitHub's secondary rate limits push back on; only reads
/// fan out. One task is one run and holds one runner slot, so
/// `--in-flight` is the count of in-flight runs. An ambiguous or
/// rate-limited answer ends the pass: the task the answer belongs to
/// has already taken its slot, and sends stay paused until the
/// backoff's wait elapses.
async fn dispatch_open(
    dispatch: &Dispatch,
    wave: &mut Wave<'_>,
    policy: &DispatchPolicy<'_>,
) -> stow_types::error::Result<()> {
    if !wave.gate.open() {
        return Ok(());
    }
    let undispatched = wave
        .open
        .iter()
        .any(|id| !wave.nodes.get(id).expect("open node").dispatched);
    if !undispatched {
        return Ok(());
    }
    // The shared margin (stow#877): `status` counts every queued and
    // in-progress `build-crate.yml` run — the scheduler's dispatches
    // and another `preheat manual` wave hold slots the wave's own run
    // list cannot see — and the wave keeps at most the budgeted share.
    // The read fails closed: no status answer, no sends this pass.
    let external = match dispatch.interface.status().await {
        Ok(occupancy) => occupancy,
        Err(error) => {
            tracing::warn!(%error, "CI occupancy read failed — holding sends this pass");
            return Ok(());
        }
    };
    let own = u32::try_from(wave.runs.len()).unwrap_or(u32::MAX);
    let own_macos = wave
        .runs
        .keys()
        .filter_map(|id| wave.nodes.get(id))
        .filter(|node| runner_family(node.request.target.as_str()) == Some(RunnerFamily::MacOs))
        .count()
        .try_into()
        .unwrap_or(u32::MAX);
    let mut taken = external.total().max(own);
    let mut taken_macos = external.of(RunnerFamily::MacOs).max(own_macos);
    for task_id in wave.open.clone() {
        if taken >= policy.in_flight.min(STOW_RUNNER_BUDGET) {
            return Ok(());
        }
        let node = wave.nodes.get(&task_id).expect("open node");
        if node.dispatched {
            continue;
        }
        let is_macos = runner_family(node.request.target.as_str()) == Some(RunnerFamily::MacOs);
        if is_macos && taken_macos >= STOW_MACOS_RUNNER_BUDGET {
            continue;
        }
        let encoded = serde_json::to_string(&task_payload(&task_id, &node.request))
            .map_err(|error| stow_error!("encode {task_id}: {error}"))?;
        match dispatch_task(dispatch, task_id, encoded, wave).await? {
            DispatchAnswer::Bound => {
                wave.gate.confirmed();
                taken += 1;
                if is_macos {
                    taken_macos += 1;
                }
            }
            DispatchAnswer::Ambiguous(failure) | DispatchAnswer::RateLimited(failure) => {
                return wave.gate.hold(&failure);
            }
        }
    }
    Ok(())
}

/// One poll iteration's resolution of dispatch answers that never
/// arrived: the listing runs from the earliest unresolved attempt's
/// wall clock (minus [`GITHUB_CLOCK_ALLOWANCE`]) to now, restricted to
/// the unresolved batches. A qualifying run binds its batch through
/// the fold — the newest when several qualify; a run created before
/// its batch's own attempt can never be that attempt's answer and is
/// dropped. An attempt still unresolved past `RUN_GRACE_MINUTES`
/// returns its nodes to unsent, and the loop dispatches them again.
async fn resolve_unanswered(
    dispatch: &Dispatch,
    wave: &mut Wave<'_>,
    main_head: &str,
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<()> {
    let floor = wave
        .runs
        .values()
        .filter_map(|run| run.unresolved.as_ref().map(|attempt| attempt.wall))
        .min();
    let Some(floor) = floor else {
        return Ok(());
    };
    let states = dispatch
        .list_runs(
            floor - GITHUB_CLOCK_ALLOWANCE,
            time::OffsetDateTime::now_utc(),
            rustc_version,
        )
        .await?;
    let mut latest = HashMap::<String, RunState>::new();
    retain_qualifying_runs(&mut latest, states, wave.runs);
    for state in latest.into_values() {
        classify_and_fold(dispatch, state, wave, main_head).await?;
    }
    let grace = std::time::Duration::from_secs(60 * RUN_GRACE_MINUTES);
    let expired: Vec<String> = wave
        .runs
        .iter()
        .filter(|(_, run)| {
            run.unresolved
                .as_ref()
                .is_some_and(|attempt| attempt.instant.elapsed() > grace)
        })
        .map(|(id, _)| id.clone())
        .collect();
    for id in expired {
        let run = wave.runs.remove(&id).expect("expired run");
        wave.nodes
            .get_mut(&run.task_id)
            .expect("task node")
            .dispatched = false;
    }
    Ok(())
}

/// Fold the listed runs into `latest` per unresolved batch: a run may
/// answer a batch's attempt only when it was created at or after the
/// attempt's wall clock minus [`GITHUB_CLOCK_ALLOWANCE`]; the local
/// server's rows carry no `created_at` and always qualify. Among the
/// qualifying runs the newest binds — `retain_latest_run` keeps the
/// highest run id, and GitHub's ids mint in creation order.
fn retain_qualifying_runs(
    latest: &mut HashMap<String, RunState>,
    states: impl IntoIterator<Item = RunState>,
    runs: &HashMap<String, BoundRun>,
) {
    for state in states {
        let Some(run) = runs.get(&state.task_id) else {
            continue;
        };
        let Some(attempt) = run.unresolved.as_ref() else {
            continue;
        };
        if state
            .created_at
            .is_some_and(|created| created < attempt.wall - GITHUB_CLOCK_ALLOWANCE)
        {
            continue;
        }
        retain_latest_run(latest, state, run.workflow_run_id);
    }
}

/// Once a layer's runs finished, publish the index — GitHub mode
/// dispatches `index-publish.yml` (the `stow_edge_url` input rides
/// `--edge-url`/`STOW_EDGE_URL`); mock mode runs export+publish in
/// subprocesses — then poll the touched slices until they serve every
/// done node of the layer.
async fn publish_and_wait(
    dispatch: &Dispatch,
    args: &ManualArgs,
    nodes: &BTreeMap<String, NodeRun>,
    layer: &[String],
    index: &Index<'_>,
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<()> {
    let mut slices: BTreeSet<TargetTriple> = BTreeSet::new();
    for id in layer {
        let node = nodes.get(id).expect("layer node");
        if node.done {
            slices.insert(node.request.target.clone());
        }
    }
    if slices.is_empty() {
        return Ok(());
    }
    match &dispatch.reads {
        DispatchReads::GitHub { token } => {
            let mut inputs = serde_json::json!({});
            if let Some(url) = args.edge_url.clone() {
                inputs["stow_edge_url"] = serde_json::Value::String(url);
            }
            inputs["rustc_version"] = serde_json::Value::String(rustc_version.to_string());
            // The publish dispatch is idempotent — a second
            // `index-publish.yml` run publishes the same slices — so an
            // answer that settled nothing simply waits the outage
            // budget out and sends again.
            let body = serde_json::json!({ "ref": BRANCH, "inputs": inputs });
            let mut backoff = Backoff::outage();
            loop {
                match crate::github::post_empty(
                    token,
                    &format!("actions/workflows/{INDEX_PUBLISH_WORKFLOW}/dispatches"),
                    &body,
                )
                .await
                {
                    Ok(()) => break,
                    Err(failure @ WriteFailure::Refused(_)) => return Err(failure.into()),
                    Err(failure) => {
                        let Some(wait) = write_hold(&mut backoff, &failure) else {
                            return Err(stow_error!(
                                "index-publish dispatch stayed unanswerable for the outage bound: {failure}"
                            ));
                        };
                        tracing::warn!(%failure, wait = ?wait, "index-publish dispatch unanswered; resending");
                        tokio::time::sleep(wait).await;
                    }
                }
            }
        }
        DispatchReads::Local { .. } => {
            local_index_publish(rustc_version).await?;
        }
    }
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(60 * PUBLISH_TIMEOUT_MINUTES);
    loop {
        // Reads fan out under the shared bound; the dispatch above stays
        // serial for GitHub's secondary rate limits.
        let served: Vec<bool> = futures_util::stream::iter(slices.iter().map(|target| async {
            let rows = published_slice_rows(index, target, rustc_version).await?;
            slice_serves_layer(rows.as_deref(), target, rustc_version, layer, nodes)
        }))
        .buffered(SLICE_PULL_CONCURRENCY)
        .try_collect()
        .await?;
        let waiting: Vec<&str> = slices
            .iter()
            .zip(&served)
            .filter(|(_, served)| !**served)
            .map(|(target, _)| target.as_str())
            .collect();
        if waiting.is_empty() {
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            return Err(stow_error!(
                "index publish did not serve the layer within {PUBLISH_TIMEOUT_MINUTES} minutes; \
                 still waiting on {}",
                waiting.join(", ")
            ));
        }
        tracing::info!(waiting = ?waiting, "layer not yet served by its published slices");
        tokio::time::sleep(std::time::Duration::from_secs(INDEX_POLL_SECONDS)).await;
    }
}

/// Does `target`'s slice (`rows`) serve every done node of this layer
/// that lives on `target`? The slice's covered set is the same one the
/// resume path marks nodes off — `covered_slice_nodes` — so a node is
/// served when its own task id (context digest included) is in it: a
/// unit the slice carries only under another dependency identity does
/// not count, and a layer node whose own row has not landed yet keeps
/// the publish wait open. A node on another target is that target's
/// slice's business: a layer spans every CI target, and no single slice
/// holds them all.
fn slice_serves_layer(
    rows: Option<&[ArtifactIndexRow]>,
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
    layer: &[String],
    nodes: &BTreeMap<String, NodeRun>,
) -> stow_types::error::Result<bool> {
    let Some(rows) = rows else {
        return Ok(false);
    };
    let spellings = nodes
        .iter()
        .map(|(id, node)| (id.clone(), node.request.explicit_spelling))
        .collect();
    let covered = covered_slice_nodes(rows, target, rustc_version, &spellings)?;
    Ok(layer.iter().all(|id| {
        let node = nodes.get(id).expect("layer node");
        !node.done || node.request.target != *target || covered.contains(id)
    }))
}

/// One `slices.json` entry's file pair.
#[derive(serde::Deserialize)]
struct SliceFile {
    index_file: String,
    folded_file: String,
}

/// The mock-mode publish: run `stow-admin index export --out-dir` once,
/// then `index publish` per `slices.json` entry — exactly the loop
/// `index-publish.yml` drives, against the mock registry.
async fn local_index_publish(rustc_version: &WireRustcVersion) -> stow_types::error::Result<()> {
    let exe = std::env::current_exe()?;
    let out_dir = std::env::temp_dir().join(format!("stow-manual-index-{}", std::process::id()));
    let status = tokio::process::Command::new(&exe)
        .arg("index")
        .arg("export")
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--rustc-version")
        .arg(rustc_version.as_str())
        .status()
        .await
        .map_err(|error| stow_error!("spawn stow-admin index export: {error}"))?;
    if !status.success() {
        return Err(stow_error!("stow-admin index export exited {status}"));
    }
    let slices: Vec<SliceFile> = serde_json::from_slice(
        &tokio::fs::read(out_dir.join("slices.json"))
            .await
            .map_err(|error| stow_error!("read slices.json: {error}"))?,
    )
    .map_err(|error| stow_error!("decode slices.json: {error}"))?;
    for slice in &slices {
        let status = tokio::process::Command::new(&exe)
            .arg("index")
            .arg("publish")
            .arg("--file")
            .arg(out_dir.join(&slice.index_file))
            .arg("--folded")
            .arg(out_dir.join(&slice.folded_file))
            .status()
            .await
            .map_err(|error| stow_error!("spawn stow-admin index publish: {error}"))?;
        if !status.success() {
            return Err(stow_error!(
                "stow-admin index publish for {} exited {status}",
                slice.index_file
            ));
        }
    }
    Ok(())
}

/// A [`CiDispatchError`] as the wave's [`WriteFailure`]: a rate limit
/// or a refused status provably did not happen; a 5xx or a transport
/// failure may have landed, so it resolves ambiguously.
fn send_failure(error: CiDispatchError) -> WriteFailure {
    match error {
        CiDispatchError::RateLimited {
            status,
            retry_after_secs,
        } => WriteFailure::RateLimited {
            message: format!("dispatch rate-limited (HTTP {status})"),
            hint: retry_after_secs.map(std::time::Duration::from_secs),
        },
        CiDispatchError::Api { status, body } if status >= 500 => {
            WriteFailure::Ambiguous(format!("dispatch: HTTP {status}: {body}"))
        }
        CiDispatchError::Api { status, body } => {
            WriteFailure::Refused(format!("dispatch: HTTP {status}: {body}"))
        }
        CiDispatchError::Network(error) | CiDispatchError::Response(error) => {
            WriteFailure::Ambiguous(format!("dispatch: {error}"))
        }
        CiDispatchError::OutOfScope(error) | CiDispatchError::TokenMint(error) => {
            WriteFailure::Refused(error)
        }
    }
}

impl Dispatch {
    /// Send the build-batch dispatch: GitHub's `workflow_dispatch` of
    /// `build-batch.yml` with the `batch` input under the operator
    /// token, or the local server's `/dispatch` POST of the same
    /// payload — and the same three-way answer either way: the run id
    /// on a confirmed send, or the [`WriteFailure`] kind an ambiguous
    /// answer resolves through.
    async fn send(&self, encoded: &str) -> Result<u64, WriteFailure> {
        self.interface
            .submit(encoded)
            .await
            .map(|run| run.workflow_run_id)
            .map_err(send_failure)
    }

    /// `main`'s head — GitHub reads it conditionally (a 304 keeps the
    /// cached sha and its etag), the local server has no ref so staleness
    /// never applies there.
    async fn refresh_head(
        &self,
        cache: &mut Option<HeadCache>,
    ) -> stow_types::error::Result<String> {
        match &self.reads {
            DispatchReads::GitHub { token } => {
                let etag = cache.as_ref().and_then(|cache| cache.etag.as_deref());
                match crate::github::get_conditional::<GitRef>(
                    token,
                    &format!("git/ref/heads/{BRANCH}"),
                    etag,
                    Backoff::outage(),
                )
                .await?
                {
                    crate::github::Conditional::Modified { body, etag } => {
                        let sha = body.object.sha;
                        *cache = Some(HeadCache {
                            sha: sha.clone(),
                            etag,
                        });
                        Ok(sha)
                    }
                    crate::github::Conditional::Unmodified => Ok(cache
                        .as_ref()
                        .expect("a 304 follows a 200 whose validator we sent")
                        .sha
                        .clone()),
                }
            }
            DispatchReads::Local { .. } => Ok(String::new()),
        }
    }

    /// Every `build-crate.yml` run of `rustc_version`'s in the closed
    /// `[since, until]` window — GitHub range-enumerates `created` so
    /// the whole window is read past the 1000-row cap; the local server
    /// answers its whole task list, each row its own task's outcome.
    async fn list_runs(
        &self,
        since: time::OffsetDateTime,
        until: time::OffsetDateTime,
        rustc_version: &WireRustcVersion,
    ) -> stow_types::error::Result<Vec<RunState>> {
        match &self.reads {
            DispatchReads::GitHub { token } => {
                let rows = crate::github::runs_in_range(
                    WORKFLOW_FILE,
                    &format!("event=workflow_dispatch&branch={BRANCH}"),
                    since,
                    until,
                    |path| async move {
                        crate::github::get::<crate::github::RunsPage<WorkflowRunRow>>(
                            token,
                            &path,
                            Backoff::outage(),
                        )
                        .await
                    },
                )
                .await?;
                Ok(rows
                    .into_iter()
                    .filter_map(|run| {
                        let (rustc, task_id) = parse_run_title(&run.display_title)?;
                        (rustc == rustc_version.as_str()).then(|| RunState {
                            task_id: task_id.to_owned(),
                            workflow_run_id: run.id,
                            status: run.status,
                            conclusion: run.conclusion,
                            url: run.html_url,
                            head_sha: run.head_sha,
                            run_attempt: run.run_attempt,
                            created_at: Some(run.created_at),
                            error: None,
                        })
                    })
                    .collect())
            }
            DispatchReads::Local { base } => local_run_states(base, rustc_version).await,
        }
    }

    /// Poll only the runs the wave is bound to: each bound batch's run
    /// id gets one conditional `actions/runs/{id}` read — a 304 keeps
    /// the batch's cached row — at the read bound of 8. A run id GitHub
    /// has not materialized yet, or a row still titled with the
    /// workflow's `name:` because `run-name` has not rendered, answers
    /// `Pending` and stays under the batch's grace. The local server
    /// keeps its `/tasks` contract: it answers the bound runs' rows
    /// from one list read.
    async fn poll_bound(
        &self,
        runs: &HashMap<String, BoundRun>,
        rustc_version: &WireRustcVersion,
    ) -> stow_types::error::Result<Vec<BoundPoll>> {
        match &self.reads {
            DispatchReads::GitHub { token } => futures_util::stream::iter(
                runs.iter()
                    .filter_map(|(task_id, run)| {
                        run.workflow_run_id
                            .map(|run_id| (task_id.clone(), run_id, run.etag.clone(), run.observed))
                    })
                    .map(|(task_id, run_id, etag, observed)| async move {
                        let path = format!("actions/runs/{run_id}");
                        match crate::github::get_conditional_result::<WorkflowRunRow>(
                            token,
                            &path,
                            etag.as_deref(),
                            Backoff::outage(),
                        )
                        .await
                        {
                            Ok(crate::github::Conditional::Unmodified) => {
                                Ok(BoundPoll::Unmodified(task_id))
                            }
                            Ok(crate::github::Conditional::Modified { body: row, etag }) => {
                                let Some(state) =
                                    bound_run_state(row, run_id, &task_id, rustc_version)?
                                else {
                                    // `Pending` leaves the run's
                                    // `etag` untouched, so the next
                                    // poll reads the row again.
                                    return untitled_run(run_id, observed);
                                };
                                Ok(BoundPoll::State {
                                    task_id,
                                    state,
                                    etag,
                                })
                            }
                            Err(zenwave::Error::Http { status, .. }) if status.as_u16() == 404 => {
                                run_404(run_id, observed)
                            }
                            Err(error) => Err(stow_error!("GET actions/runs/{run_id}: {error}")),
                        }
                    }),
            )
            .buffered(SLICE_PULL_CONCURRENCY)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect(),
            DispatchReads::Local { base } => {
                // The same tracked-id binding GitHub gets: a local row
                // that is not the task's bound run id is dropped
                // before the fold, so an old same-task completion can
                // never answer a newer bound retry.
                let bound: BTreeSet<u64> = runs
                    .values()
                    .filter_map(|run| run.workflow_run_id)
                    .collect();
                Ok(local_run_states(base, rustc_version)
                    .await?
                    .into_iter()
                    .filter(|state| bound.contains(&state.workflow_run_id))
                    .map(|state| BoundPoll::State {
                        task_id: state.task_id.clone(),
                        state,
                        etag: None,
                    })
                    .collect())
            }
        }
    }
}

/// The `overdue` predicate: a dispatch GitHub confirmed with a run id —
/// `dispatched_at` was taken — whose run never materialized inside the
/// grace window. An unresolved batch holds no confirmed id and no
/// `dispatched_at`, so it can never be overdue: its own grace lives on
/// the attempt's `instant` instead.
fn dispatch_overdue(batch: &BoundRun) -> bool {
    batch.workflow_run_id.is_some()
        && !batch.observed
        && batch.dispatched_at.is_some_and(|since| {
            since.elapsed() > std::time::Duration::from_secs(60 * RUN_GRACE_MINUTES)
        })
}

/// One bound run's poll answer: a fresh row to fold, `Unmodified` when
/// the batch's cached row still stands (the fold re-judges it against
/// the current `main` head), `Pending` when the run id has not
/// materialized or its row's title has not rendered yet.
enum BoundPoll {
    State {
        task_id: String,
        state: RunState,
        etag: Option<String>,
    },
    Unmodified(String),
    Pending,
}

/// A bound run's 404: an id that already materialized — the node
/// observed its row — is GitHub dropping a run, which is a clear error;
/// only a fresh dispatch id that has never been seen waits out its
/// grace window as `Pending`.
fn run_404(run_id: u64, observed: bool) -> stow_types::error::Result<BoundPoll> {
    if observed {
        Err(stow_error!(
            "workflow run {run_id} was observed and now answers 404 — GitHub dropped a materialized run"
        ))
    } else {
        Ok(BoundPoll::Pending)
    }
}

/// A bound run's row before GitHub has rendered its title: a dispatch
/// id the node has never read a state from is still materializing and
/// waits out its grace window as `Pending`, like a 404. A node that
/// already read a titled row cannot meet an untitled one — that is
/// GitHub answering with something else.
fn untitled_run(run_id: u64, observed: bool) -> stow_types::error::Result<BoundPoll> {
    if observed {
        Err(stow_error!(
            "workflow run {run_id} was observed and now answers with the workflow's name for a title"
        ))
    } else {
        Ok(BoundPoll::Pending)
    }
}

/// `main`'s cached head for one layer — the sha and the validator that
/// turns the next read into a 304.
struct HeadCache {
    sha: String,
    etag: Option<String>,
}

/// Fold a `GET actions/runs/{id}` row into a run state: the row's own id
/// must be the bound one and its `display_title` the task's
/// `<rustc>-<task_id>` — anything else means GitHub answered for a
/// different run, which is never a state this task may take. A row still
/// titled with the workflow's own `name:` is GitHub not having rendered
/// `run-name` yet — `Ok(None)`, a title pending rather than a state.
fn bound_run_state(
    row: WorkflowRunRow,
    run_id: u64,
    task_id: &str,
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<Option<RunState>> {
    if row.id != run_id {
        return Err(stow_error!(
            "actions/runs/{run_id} answered with run {} — binding refused",
            row.id
        ));
    }
    if row.display_title == WORKFLOW_NAME {
        return Ok(None);
    }
    let Some((rustc, title_task)) = parse_run_title(&row.display_title) else {
        return Err(stow_error!(
            "actions/runs/{run_id} title {:?} is not a task title",
            row.display_title
        ));
    };
    if rustc != rustc_version.as_str() || title_task != task_id {
        return Err(stow_error!(
            "actions/runs/{run_id} title {:?} does not match bound task {task_id}",
            row.display_title
        ));
    }
    Ok(Some(RunState {
        task_id: title_task.to_owned(),
        workflow_run_id: row.id,
        status: row.status,
        conclusion: row.conclusion,
        url: row.html_url,
        head_sha: row.head_sha,
        run_attempt: row.run_attempt,
        created_at: Some(row.created_at),
        error: None,
    }))
}

/// The local CI server's `/tasks` rows folded to run states — one
/// `RunState` per task run of this wave's rustc, its status,
/// conclusion and error riding the row directly.
async fn local_run_states(
    base: &str,
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<Vec<RunState>> {
    let url = format!("{base}/tasks");
    // The shared bounded idempotent read — the local server is
    // unauthenticated, so no operator token rides it.
    let tasks: stow_types::local_ci::LocalCiTasks =
        crate::github::get_url_json(&url, None, Backoff::new()).await?;
    Ok(tasks
        .tasks
        .iter()
        .filter_map(|run| {
            let (rustc, task_id) = parse_run_title(&run.display_title)?;
            (rustc == rustc_version.as_str()).then(|| RunState {
                task_id: task_id.to_owned(),
                workflow_run_id: run.workflow_run_id,
                status: run.status.clone(),
                conclusion: run.conclusion.clone(),
                url: run.html_url.clone(),
                head_sha: String::new(),
                run_attempt: 1,
                created_at: None,
                error: run.error.clone(),
            })
        })
        .collect())
}

/// The layer's one-time adoption sweep: every `build-crate.yml` run in
/// the closed `[adopt_since, now]` window, newest first so the newest
/// run covering a node binds it. The run's title names its task id —
/// an undispatched open node binds the run and folds through the same
/// path a bound poll takes.
async fn adopt_runs(
    dispatch: &Dispatch,
    wave: &mut Wave<'_>,
    adopt_since: time::OffsetDateTime,
    rustc_version: &WireRustcVersion,
    main_head: &str,
) -> stow_types::error::Result<()> {
    if wave.open.is_empty() {
        return Ok(());
    }
    let mut states = dispatch
        .list_runs(adopt_since, time::OffsetDateTime::now_utc(), rustc_version)
        .await?;
    // Newest first: the newest run covering a node wins its binding.
    states.sort_by_key(|state| std::cmp::Reverse(state.workflow_run_id));
    for state in states {
        // A run's staleness is on its row — a stale run's node never
        // binds.
        if state.stale_failure(main_head) {
            continue;
        }
        // The run's title gives its task id — one task is one run.
        let Some(node) = wave.nodes.get_mut(&state.task_id) else {
            continue;
        };
        if node.dispatched {
            continue;
        }
        node.dispatched = true;
        node.run_url = Some(state.url.clone());
        node.workflow_run_id = Some(state.workflow_run_id);
        wave.runs.insert(
            state.task_id.clone(),
            BoundRun {
                task_id: state.task_id.clone(),
                workflow_run_id: Some(state.workflow_run_id),
                run_url: Some(state.url.clone()),
                etag: None,
                latest: None,
                observed: true,
                unresolved: None,
                pending_rerun: None,
                dispatched_at: None,
            },
        );
        classify_and_fold(dispatch, state, wave, main_head).await?;
    }
    Ok(())
}

/// `GET /git/ref/heads/{branch}` — the fields the driver needs.
#[derive(serde::Deserialize)]
struct GitRef {
    object: GitRefObject,
}

#[derive(serde::Deserialize)]
struct GitRefObject {
    sha: String,
}

#[cfg(test)]
mod tests {
    fn local_dispatch(base: &str) -> Dispatch {
        Dispatch {
            interface: CiInterface::local_ci(base, ZenwaveTransport),
            reads: DispatchReads::Local {
                base: base.to_owned(),
            },
        }
    }

    use super::*;
    use crate::runs::TaskFailure;
    use clap::Parser;
    use stow_types::api::TaskHash;
    use stow_types::runs::{RunJobRow, RunStepRow};

    /// `main`'s sha in the test fixtures.
    const MAIN_HEAD: &str = "1111111111111111111111111111111111111111";

    /// A rate limit's own stated wait closes the write gate for exactly
    /// that duration — past the retry-after ceiling and outside the
    /// outage budget, so an ambiguous answer right after it still gets
    /// the budget's first wait.
    #[tokio::test(start_paused = true)]
    async fn a_rate_limit_hold_keeps_its_stated_wait_outside_the_budget() {
        let mut gate = WriteGate::new();
        let wait = std::time::Duration::from_mins(40);
        gate.hold(&WriteFailure::RateLimited {
            message: "limited".to_owned(),
            hint: Some(wait),
        })
        .expect("a stated wait always holds");
        assert!(!gate.open());
        tokio::time::advance(
            wait.checked_sub(std::time::Duration::from_secs(1))
                .expect("the hold is longer than a second"),
        )
        .await;
        assert!(!gate.open(), "the gate holds the whole stated wait");
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        assert!(gate.open());
        // The outage budget never saw the hold: the next unsettled
        // answer still gets the first doubling wait.
        gate.hold(&WriteFailure::Ambiguous("unknown".to_owned()))
            .expect("the budget is intact");
        assert!(!gate.open());
        tokio::time::advance(std::time::Duration::from_millis(600)).await;
        assert!(gate.open(), "the ambiguous hold was the first-budget wait");
    }

    /// stow#558: `preheat manual --projects` accepts `--source-trees`;
    /// without `--projects` it is a clap error before any file is read.
    #[test]
    fn the_source_trees_flag_requires_projects() {
        let cli = crate::Cli::try_parse_from([
            "stow-admin",
            "preheat",
            "manual",
            "--projects",
            "list.toml",
            "--rustc-version",
            "1.99.0",
            "--source-trees",
            "trees.toml",
        ])
        .expect("manual --projects accepts --source-trees");
        let crate::Command::Preheat(preheat) = &cli.command else {
            panic!("expected preheat");
        };
        let crate::preheat::PreheatCommand::Manual(manual) = &preheat.command else {
            panic!("expected manual");
        };
        assert_eq!(
            manual.source_trees.as_deref(),
            Some(std::path::Path::new("trees.toml")),
            "the flag lands on the manual args"
        );

        for argv in [
            [
                "stow-admin",
                "preheat",
                "manual",
                "--rustc-version",
                "1.99.0",
                "--source-trees",
                "trees.toml",
            ]
            .as_slice(),
            [
                "stow-admin",
                "preheat",
                "manual",
                "--crates",
                "c.txt",
                "--rustc-version",
                "1.99.0",
                "--source-trees",
                "trees.toml",
            ]
            .as_slice(),
            [
                "stow-admin",
                "preheat",
                "manual",
                "--dirs",
                "a,b",
                "--rustc-version",
                "1.99.0",
                "--source-trees",
                "trees.toml",
            ]
            .as_slice(),
        ] {
            assert!(
                crate::Cli::try_parse_from(argv).is_err(),
                "{argv:?} cannot take --source-trees"
            );
        }
    }

    /// Only a finished, unsuccessful run of older code is dispatched
    /// again; everything else is adopted as the run says. A cached row
    /// re-judges staleness against the poll's own `main` head — a head
    /// that moved stales a row that had read as current.
    #[test]
    fn only_a_failure_on_older_code_is_retried() {
        assert!(run_state("completed", Some("failure"), false).stale_failure(MAIN_HEAD));
        assert!(run_state("completed", Some("cancelled"), false).stale_failure(MAIN_HEAD));
        assert!(!run_state("completed", Some("failure"), true).stale_failure(MAIN_HEAD));
        assert!(!run_state("completed", Some("success"), false).stale_failure(MAIN_HEAD));
        assert!(!run_state("in_progress", None, false).stale_failure(MAIN_HEAD));
        // The local server's rows carry no sha and are never stale.
        let local = RunState {
            head_sha: String::new(),
            ..run_state("completed", Some("failure"), false)
        };
        assert!(!local.stale_failure(""));
    }

    /// A run's staleness follows `main`'s head, not the row's arrival
    /// poll: a 304-cached row folded under a moved head is stale.
    #[test]
    fn a_cached_row_stales_when_main_moves() {
        let state = run_state("completed", Some("failure"), true);
        assert!(!state.stale_failure(MAIN_HEAD));
        assert!(state.stale_failure("9999999999999999999999999999999999999999"));
    }

    /// The smallest `EnqueueRequest` `build_graph` can fold — the test
    /// graph's task ids come from it.
    fn request(
        crate_name: &str,
        target: &str,
        host_side: bool,
        deps: &[(&str, &str, bool)],
    ) -> EnqueueRequest {
        // Fixture deps carry no children of their own — each is a
        // leaf-context node, so `depends_on()`/`dependency_identity()`
        // derive the same ids the old stored fields did (stow#588).
        let depends_on: Vec<_> = deps
            .iter()
            .map(|(name, dep_target, dep_host)| EnqueueDependency {
                crate_name: CrateName::parse(*name).expect("dep name"),
                version: CrateVersion(semver::Version::new(1, 0, 0)),
                features_json: stow_types::identity::FeaturesJson::default(),
                target: TargetTriple::parse(*dep_target).expect("dep target"),
                rustc_version: WireRustcVersion::parse("1.99.0").expect("dep rustc"),
                host_side: *dep_host,
                explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
                dependency_identity: stow_types::identity::DependencyIdentity::leaf()
                    .expect("leaf identity"),
            })
            .collect();
        let dependency_subgraph = stow_types::api::TaskSubgraph {
            root_deps: (0..u32::try_from(depends_on.len()).expect("test dep count")).collect(),
            nodes: depends_on
                .iter()
                .map(|dep| stow_types::api::SubgraphNode {
                    crate_name: dep.crate_name.clone(),
                    version: dep.version.clone(),
                    features_json: dep.features_json.clone(),
                    host_side: dep.host_side,
                    keys_apart: false,
                    deps: Vec::new(),
                })
                .collect(),
        };
        EnqueueRequest {
            crate_name: CrateName::parse(crate_name).expect("crate name"),
            version: CrateVersion(semver::Version::new(1, 0, 0)),
            features_json: stow_types::identity::FeaturesJson::canonicalize(Vec::new())
                .expect("empty features"),
            target: TargetTriple::parse(target).expect("target"),
            rustc_version: WireRustcVersion::parse("1.99.0").expect("rustc"),
            downloads: 0,
            source: stow_types::api::EnqueueSource::CacheMiss,
            dependency_subgraph,
            preserve_lockfile: false,
            host_side,
            explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
        }
    }

    /// A failed ancestor skips its dependents — and transitively the
    /// dependents of skipped nodes — naming the failed node as the
    /// blocker. Covered, unrelated and already-done nodes stay open.
    #[test]
    fn a_failed_dependency_skips_its_dependents() {
        const T: &str = "x86_64-unknown-linux-gnu";
        // leaf <- mid <- top, plus an unrelated independent node.
        let mid = request("mid", T, false, &[("leaf", T, false)]);
        let mut top = request("top", T, false, &[("mid", T, false)]);
        // mid's own child rides inside top's subgraph — the derived
        // digest then matches mid's real task id.
        top.dependency_subgraph
            .nodes
            .push(stow_types::api::SubgraphNode {
                crate_name: CrateName::parse("leaf").expect("dep name"),
                version: CrateVersion(semver::Version::new(1, 0, 0)),
                features_json: stow_types::identity::FeaturesJson::default(),
                host_side: false,
                keys_apart: false,
                deps: Vec::new(),
            });
        top.dependency_subgraph.nodes[0].deps = vec![1];
        let requests = vec![
            request("leaf", T, false, &[]),
            mid,
            top,
            request("other", T, false, &[]),
        ];
        let (mut nodes, edges) = build_graph(requests).expect("valid graph");
        let ids = |name: &str| node_task_id(request_by_name(name, &nodes)).expect("task id");
        let (leaf, mid, top, other) = (ids("leaf"), ids("mid"), ids("top"), ids("other"));

        nodes.get_mut(&leaf).expect("leaf").failed = true;
        // mark_blocked runs per layer, mirroring the driver's loop —
        // mid sits a layer above leaf, top a layer above mid.
        let layer = [mid.clone(), other.clone()];
        let blocked = mark_blocked(&layer, &mut nodes, &edges);
        assert_eq!(
            blocked,
            vec![(mid, leaf.clone())],
            "mid is skipped naming leaf"
        );
        // Transitive: once mid is blocked, top names leaf — the failed
        // ancestor, not the skipped intermediate.
        let blocked = mark_blocked(std::slice::from_ref(&top), &mut nodes, &edges);
        assert_eq!(blocked, vec![(top, leaf)]);
        assert!(nodes.get(&other).expect("other").blocked_by.is_none());
        // A node that already ran is never re-marked.
        nodes.get_mut(&other).expect("other").done = true;
        let blocked = mark_blocked(std::slice::from_ref(&other), &mut nodes, &edges);
        assert_eq!(
            blocked,
            [] as [(std::string::String, std::string::String); 0]
        );
    }

    /// One published row for `request` at `shape`.
    fn row_for(
        request: &EnqueueRequest,
        shape: stow_types::public_cache::UnitShape,
    ) -> ArtifactIndexRow {
        ArtifactIndexRow {
            crate_name: request.crate_name.clone(),
            version: request.version.clone(),
            features_json: request.features_json.clone(),
            dependency_c_metadata_json: stow_types::identity::DependencyCMetadataJson::default(),
            c_metadata: stow_types::identity::CMetadata::parse("0123456789abcdef")
                .expect("c_metadata"),
            compile_key: "0123456789abcdef".repeat(4),
            bundle_digest: format!("sha256:{}", "0".repeat(64)),
            bundle_size: 1,
            artifact_kind: stow_types::artifact::ArtifactKind::Rlib,
            crate_types: vec![stow_types::artifact::RustCrateType::Rlib],
            profile: stow_types::platform::Profile {
                opt_level: "3".to_owned(),
                debuginfo: 0,
                debug_assertions: false,
                overflow_checks: false,
                panic: stow_types::platform::PanicStrategy::Unwind,
                strip: stow_types::platform::StripLevel::None,
            },
            emit: vec!["link".to_owned(), "metadata".to_owned()],
            min_glibc: None,
            unit_shape: shape,
            dependency_identity: request.dependency_identity().expect("digest"),
        }
    }

    #[test]
    fn contextual_graph_keeps_equal_parents_over_different_children() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let left = request("parent", T, false, &[("left", T, false)]);
        let right = request("parent", T, false, &[("right", T, false)]);
        let left_id = left.task_id().expect("left id");
        let right_id = right.task_id().expect("right id");
        assert_ne!(left_id, right_id);
        let (nodes, edges) = build_graph(vec![left, right]).expect("valid contexts");
        assert_eq!(nodes.len(), 2);
        assert_ne!(edges[&left_id], edges[&right_id]);
    }

    #[test]
    fn contextual_graph_rejects_relabelled_edges() {
        let mut parent = request(
            "parent",
            "x86_64-unknown-linux-gnu",
            false,
            &[("child", "x86_64-unknown-linux-gnu", false)],
        );
        // A subgraph whose edges escape its own closure cannot
        // resolve — the request is rejected rather than keyed.
        parent.dependency_subgraph.root_deps = vec![9];
        assert!(build_graph(vec![parent]).is_err());
    }

    #[test]
    fn contextual_coverage_does_not_merge_shapes_or_unknown_contexts() {
        const T: &str = "wasm32-unknown-unknown";
        let target = TargetTriple::parse(T).expect("target");
        let left = request("parent", T, false, &[("left", T, false)]);
        let right = request("parent", T, false, &[("right", T, false)]);
        let shapes = required_unit_shapes(
            false,
            UnitInvocation::Target,
            stow_types::public_cache::ExplicitSpelling::KeysAsNative,
        );
        let rows = shapes
            .iter()
            .map(|shape| row_for(&left, *shape))
            .collect::<Vec<_>>();
        let covered =
            super::covered_slice_nodes(&rows, &target, &left.rustc_version, &BTreeMap::new())
                .expect("coverage");
        assert!(covered.contains(&left.task_id().expect("left id")));
        assert!(!covered.contains(&right.task_id().expect("right id")));

        let mut mixed = rows;
        mixed[0].dependency_identity = right.dependency_identity().expect("right digest");
        assert!(
            super::covered_slice_nodes(&mixed, &target, &left.rustc_version, &BTreeMap::new())
                .expect("mixed coverage")
                .is_empty()
        );
    }

    #[test]
    fn contextual_host_coverage_requires_both_invocation_spellings() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let target = TargetTriple::parse(T).expect("target");
        let host = request("helper", T, true, &[]);
        let rows = required_unit_shapes(
            true,
            UnitInvocation::Native,
            stow_types::public_cache::ExplicitSpelling::KeysAsNative,
        )
        .into_iter()
        .map(|shape| row_for(&host, shape))
        .collect::<Vec<_>>();
        assert!(
            rows.iter()
                .any(|row| row.unit_shape.invocation == UnitInvocation::Target)
        );
        let complete =
            super::covered_slice_nodes(&rows, &target, &host.rustc_version, &BTreeMap::new())
                .expect("host coverage");
        assert!(complete.contains(&host.task_id().expect("host id")));
        let partial = rows
            .into_iter()
            .filter(|row| row.unit_shape.invocation == UnitInvocation::Native)
            .collect::<Vec<_>>();
        assert!(
            super::covered_slice_nodes(&partial, &target, &host.rustc_version, &BTreeMap::new())
                .expect("partial host coverage")
                .is_empty()
        );
    }

    #[test]
    fn dispatch_payload_preserves_root_and_dependency_contexts() {
        let parent = request(
            "parent",
            "wasm32-unknown-unknown",
            false,
            &[("helper", "x86_64-unknown-linux-gnu", true)],
        );
        let payload = super::task_payload(&parent.task_id().expect("parent id"), &parent);
        let graph = payload
            .verified_dependency_graph()
            .expect("payload subgraph verifies against task_id");
        assert_eq!(
            graph.dependency_identity(0).expect("root digest"),
            &parent.dependency_identity().expect("parent digest")
        );
        let helper = payload
            .dependency_subgraph
            .nodes
            .iter()
            .find(|node| node.host_side)
            .expect("host-side dep node");
        assert_eq!(helper.crate_name.as_str(), "helper");
        assert_eq!(
            graph.dependency_identity(1).expect("dep digest"),
            &parent.depends_on().expect("deps")[0].dependency_identity
        );
    }

    /// A layer spans every CI target, and each slice holds only its own
    /// target's nodes: a slice serves the layer once it carries the done
    /// nodes that live on it, whatever the other targets' nodes are.
    #[test]
    fn each_slice_serves_only_its_own_targets_nodes() {
        const HOST: &str = "x86_64-unknown-linux-gnu";
        const WASM: &str = "wasm32-unknown-unknown";
        let rustc = WireRustcVersion::parse("1.99.0").expect("rustc");
        let (mut nodes, _) = build_graph(vec![
            request("macro-dep", HOST, true, &[]),
            request("lib", WASM, false, &[]),
        ])
        .expect("valid graph");
        for node in nodes.values_mut() {
            node.done = true;
        }
        let layer: Vec<String> = nodes.keys().cloned().collect();
        let host = TargetTriple::parse(HOST).expect("host");
        let wasm = TargetTriple::parse(WASM).expect("wasm");
        let rows_for = |name: &str, invocation: UnitInvocation, host_side: bool| {
            let request = request_by_name(name, &nodes);
            required_unit_shapes(host_side, invocation, request.explicit_spelling)
                .into_iter()
                .map(|shape| row_for(request, shape))
                .collect::<Vec<_>>()
        };
        let host_rows = rows_for("macro-dep", UnitInvocation::Native, true);
        let wasm_rows = rows_for("lib", UnitInvocation::Target, false);

        assert!(slice_serves_layer(Some(&host_rows), &host, &rustc, &layer, &nodes).expect("host"));
        assert!(slice_serves_layer(Some(&wasm_rows), &wasm, &rustc, &layer, &nodes).expect("wasm"));
        // A slice still missing one of its own nodes does not serve.
        assert!(!slice_serves_layer(Some(&[]), &wasm, &rustc, &layer, &nodes).expect("empty wasm"));
        assert!(!slice_serves_layer(None, &host, &rustc, &layer, &nodes).expect("no host slice"));
    }

    /// stow#657: two nodes that differ only in dependency context can
    /// publish the very same unit — one `c_metadata` at one
    /// `unit_shape`, a row each. `covered_slice_nodes` covers both
    /// nodes, and `slice_serves_layer` — answering through it — serves
    /// the layer only once a node's own row is there, not when the
    /// slice carries the same crate, version and features under the
    /// other node's context.
    #[test]
    fn a_unit_published_by_two_contexts_serves_only_its_own_nodes() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let target = TargetTriple::parse(T).expect("target");
        let rustc = WireRustcVersion::parse("1.99.0").expect("rustc");
        let left = request("parent", T, false, &[("left", T, false)]);
        let right = request("parent", T, false, &[("right", T, false)]);
        let left_id = left.task_id().expect("left id");
        let right_id = right.task_id().expect("right id");
        assert_ne!(left_id, right_id);
        let rows_for = |request: &EnqueueRequest| {
            required_unit_shapes(
                request.host_side,
                UnitInvocation::Native,
                request.explicit_spelling,
            )
            .into_iter()
            .map(|shape| row_for(request, shape))
            .collect::<Vec<_>>()
        };
        // The two nodes' rows name the same unit — `row_for` keys them
        // on one `c_metadata` — under each node's own context.
        let left_rows = rows_for(&left);
        let right_rows = rows_for(&right);
        let all_rows = [left_rows, right_rows.clone()].concat();

        let covered = super::covered_slice_nodes(&all_rows, &target, &rustc, &BTreeMap::new())
            .expect("coverage");
        assert!(covered.contains(&left_id));
        assert!(covered.contains(&right_id));

        let (mut nodes, _) = build_graph(vec![left, right]).expect("valid graph");
        nodes.get_mut(&left_id).expect("left node").done = true;
        let layer = vec![left_id.clone()];
        // The same crate, version and feature set under the other
        // node's context alone does not serve this node.
        assert!(
            !slice_serves_layer(Some(&right_rows), &target, &rustc, &layer, &nodes)
                .expect("other context")
        );
        // With its own row published, the slice serves it.
        assert!(
            slice_serves_layer(Some(&all_rows), &target, &rustc, &layer, &nodes)
                .expect("own context")
        );
    }

    fn request_by_name<'a>(name: &str, nodes: &'a BTreeMap<String, NodeRun>) -> &'a EnqueueRequest {
        nodes
            .values()
            .find(|node| node.request.crate_name.as_str() == name)
            .map(|node| &node.request)
            .expect("node by name")
    }

    fn run_row(
        workflow_run_id: u64,
        title: &str,
        status: &str,
        conclusion: Option<&str>,
    ) -> WorkflowRunRow {
        WorkflowRunRow {
            id: workflow_run_id,
            display_title: title.to_owned(),
            head_sha: MAIN_HEAD.to_owned(),
            status: status.to_owned(),
            conclusion: conclusion.map(str::to_owned),
            html_url: format!("https://github.com/water-rs/stow/actions/runs/{workflow_run_id}"),
            run_attempt: 1,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            actor: crate::github::Actor {
                login: "test-actor".to_owned(),
            },
        }
    }

    /// A 404 on an id whose row was already observed is GitHub dropping
    /// a materialized run — an error. Only a fresh id that never
    /// materialized waits its grace as `Pending`.
    #[test]
    fn a_404_on_an_observed_run_is_missing_not_pending() {
        assert!(run_404(50, true).is_err());
        assert!(matches!(run_404(50, false), Ok(BoundPoll::Pending)));
    }

    /// An untitled row waits like a 404 — only before the node's first
    /// state. A node that already read its run titled cannot meet the
    /// workflow's `name:` again.
    #[test]
    fn an_untitled_run_waits_only_before_its_first_state() {
        assert!(matches!(untitled_run(50, false), Ok(BoundPoll::Pending)));
        assert!(untitled_run(50, true).is_err());
    }

    /// The constant and the workflow file cannot drift: the YAML must
    /// declare the `name:` the constant spells.
    #[test]
    fn the_trusted_workflow_declares_the_name_the_constant_spells() {
        let yaml = include_str!("../../.github/workflows/build-crate.yml");
        let declared = format!("name: {}", stow_types::trusted_builder::WORKFLOW_NAME);
        assert!(
            yaml.lines().any(|line| line == declared),
            "build-crate.yml must declare `{declared}`"
        );
    }

    fn all_done(crates: &[&str]) -> BTreeMap<String, NodeRun> {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) = build_graph(
            crates
                .iter()
                .map(|name| request(name, T, false, &[]))
                .collect(),
        )
        .expect("valid graph");
        for node in nodes.values_mut() {
            node.done = true;
        }
        nodes
    }

    /// stow#572: a `--projects` repository that failed to resolve does
    /// not stop the wave, but the report names every one with its
    /// reason and the run exits non-zero — even when every dispatched
    /// node built.
    #[test]
    fn finish_report_fails_on_unresolved_projects() {
        let nodes = all_done(&["built"]);
        let unresolved = vec![
            "https://github.com/a/one: fetch failed".to_owned(),
            "https://github.com/b/two: no rust manifest".to_owned(),
        ];
        let message = finish_report(&nodes, 0, &[], &[], &[], &unresolved)
            .expect_err("unresolved projects fail the wave")
            .to_string();
        for entry in &unresolved {
            assert!(message.contains(entry), "{message}");
        }
    }

    /// Every node done and every project resolved is the only Ok.
    #[test]
    fn finish_report_ok_when_all_done_and_resolved() {
        let nodes = all_done(&["built"]);
        finish_report(&nodes, 0, &[], &[], &[], &[]).expect("a clean wave");
    }

    /// A wall-clock timestamp for the resolution tests.
    fn at(unix: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(unix).expect("timestamp")
    }

    /// stow#656: a node the published index already serves lands in no
    /// layer at all, and a dependent of a covered node owes no layer
    /// for it — it sits in layer 0.
    #[test]
    fn a_covered_node_lands_in_no_layer() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let covered_leaf = request("served", T, false, &[]);
        let dependent = request("dependent", T, false, &[("served", T, false)]);
        let covered_id = covered_leaf.task_id().expect("served id");
        let dependent_id = dependent.task_id().expect("dependent id");
        let (nodes, edges) = build_graph(vec![covered_leaf, dependent]).expect("valid graph");
        let covered = BTreeSet::from([covered_id.clone()]);
        let layers = layer_graph(&nodes, &edges, &covered).expect("layers");
        assert!(
            layers.iter().all(|layer| !layer.contains(&covered_id)),
            "the covered node is in no layer"
        );
        assert_eq!(layers, vec![vec![dependent_id]]);
    }

    /// An undone node and an unresolved project both land in the error.
    #[test]
    fn finish_report_names_undone_and_unresolved() {
        let (nodes, _) = build_graph(vec![request(
            "undone",
            "x86_64-unknown-linux-gnu",
            false,
            &[],
        )])
        .expect("valid graph");
        let id = node_task_id(request_by_name("undone", &nodes)).expect("task id");
        let unresolved = vec!["https://github.com/a/one: fetch failed".to_owned()];
        let message = finish_report(
            &nodes,
            0,
            &[(id.clone(), "http://localhost/run/1".to_owned())],
            &[],
            &[],
            &unresolved,
        )
        .expect_err("an undone node plus an unresolved project fails")
        .to_string();
        assert!(message.contains(&id), "{message}");
        assert!(message.contains(&unresolved[0]), "{message}");
    }

    /// stow#736: a `KeysApart` node published before the flag existed
    /// carries only its native shapes — its explicit `--target`
    /// spellings never shipped — so the index-rooted resume must not
    /// call it done: it dispatches again under the same task id.
    #[test]
    fn a_flagged_node_published_native_only_is_not_covered() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let target = TargetTriple::parse(T).expect("target");
        let mut flagged = request("lib", T, false, &[]);
        flagged.explicit_spelling = stow_types::public_cache::ExplicitSpelling::KeysApart;
        let id = flagged.task_id().expect("task id");
        // The flag is semantic data, never identity — the same node
        // mints the same task id either way.
        let plain = request("lib", T, false, &[]);
        assert_eq!(id, plain.task_id().expect("task id"));
        let spellings = BTreeMap::from([(
            id.clone(),
            stow_types::public_cache::ExplicitSpelling::KeysApart,
        )]);
        let native_only = required_unit_shapes(
            false,
            UnitInvocation::Native,
            stow_types::public_cache::ExplicitSpelling::KeysAsNative,
        )
        .into_iter()
        .map(|shape| row_for(&flagged, shape))
        .collect::<Vec<_>>();
        assert!(
            super::covered_slice_nodes(&native_only, &target, &flagged.rustc_version, &spellings)
                .expect("coverage")
                .is_empty(),
            "a KeysApart node with only its native shapes is not done"
        );
        let all = required_unit_shapes(
            false,
            UnitInvocation::Native,
            stow_types::public_cache::ExplicitSpelling::KeysApart,
        )
        .into_iter()
        .map(|shape| row_for(&flagged, shape))
        .collect::<Vec<_>>();
        assert!(
            super::covered_slice_nodes(&all, &target, &flagged.rustc_version, &spellings)
                .expect("coverage")
                .contains(&id),
            "all four shapes published is done"
        );
    }

    /// The task id a fixture run's title carries — `run_state_with_id`
    /// and `bound_run` agree on it.
    fn task_id_for(run_id: u64) -> String {
        format!("task-{run_id}")
    }

    fn run_state(status: &str, conclusion: Option<&str>, ran_current_code: bool) -> RunState {
        run_state_with_id(1, status, conclusion, ran_current_code)
    }

    fn run_state_with_id(
        workflow_run_id: u64,
        status: &str,
        conclusion: Option<&str>,
        ran_current_code: bool,
    ) -> RunState {
        RunState {
            task_id: task_id_for(workflow_run_id),
            workflow_run_id,
            status: status.to_owned(),
            conclusion: conclusion.map(str::to_owned),
            url: format!("https://github.com/water-rs/stow/actions/runs/{workflow_run_id}"),
            head_sha: if ran_current_code {
                MAIN_HEAD.to_owned()
            } else {
                "2222222222222222222222222222222222222222".to_owned()
            },
            run_attempt: 1,
            created_at: None,
            error: None,
        }
    }

    /// One GitHub jobs-page row: `steps` as `(name, status,
    /// conclusion)` triples, times present so a successful leg reads
    /// its `started_at`/`completed_at` edges.
    fn job_row(
        name: &str,
        status: &str,
        conclusion: Option<&str>,
        steps: &[(&str, &str, Option<&str>)],
    ) -> RunJobRow {
        RunJobRow {
            id: 1,
            name: name.to_owned(),
            status: status.to_owned(),
            conclusion: conclusion.map(str::to_owned),
            started_at: Some(at(0)),
            completed_at: Some(at(60)),
            run_attempt: 1,
            html_url: "https://github.com/water-rs/stow/actions/runs/50/job/1".to_owned(),
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

    /// A bound run carrying `task_id`'s node, on run `run_id`,
    /// observed, with the expected hash a minted dispatch would.
    fn bound_run(task_id: &str, run_id: u64) -> BoundRun {
        BoundRun {
            task_id: task_id.to_owned(),
            workflow_run_id: Some(run_id),
            run_url: Some(format!(
                "https://github.com/water-rs/stow/actions/runs/{run_id}"
            )),
            etag: None,
            latest: None,
            observed: true,
            unresolved: None,
            pending_rerun: None,
            dispatched_at: Some(std::time::Instant::now()),
        }
    }

    /// A run whose dispatch answer never arrived — its node is held
    /// `dispatched` while the resolution listing settles it.
    fn unresolved_run(
        runs: &mut HashMap<String, BoundRun>,
        nodes: &mut BTreeMap<String, NodeRun>,
        task_id: &str,
        run_id: u64,
        wall: time::OffsetDateTime,
    ) {
        nodes.get_mut(task_id).expect("task node").dispatched = true;
        runs.insert(
            task_id.to_owned(),
            BoundRun {
                task_id: task_id.to_owned(),
                workflow_run_id: Some(run_id),
                run_url: None,
                etag: None,
                latest: None,
                observed: false,
                unresolved: Some(UnansweredDispatch {
                    wall,
                    instant: tokio::time::Instant::now(),
                }),
                pending_rerun: None,
                dispatched_at: None,
            },
        );
    }

    /// Wire a `Wave` over the fixture pieces — the same fields
    /// `drive_layer` wires.
    fn wave<'a>(
        nodes: &'a mut BTreeMap<String, NodeRun>,
        open: &'a mut BTreeSet<String>,
        runs: &'a mut HashMap<String, BoundRun>,
        reruns: &'a mut Vec<RerunRecord>,
        gate: &'a mut WriteGate,
    ) -> Wave<'a> {
        Wave {
            nodes,
            open,
            runs,
            reruns,
            gate,
        }
    }

    #[test]
    fn numeric_latest_run_wins_over_unordered_old_failure() {
        let mut latest = HashMap::new();
        let batch = task_id_for(1);
        let mut newer = run_state_with_id(10, "in_progress", None, true);
        newer.task_id = batch.clone();
        let mut older = run_state_with_id(9, "completed", Some("failure"), false);
        older.task_id = batch.clone();
        retain_latest_run(&mut latest, newer, None);
        retain_latest_run(&mut latest, older, None);
        let selected = latest.remove(&batch).expect("latest run");
        assert_eq!(selected.workflow_run_id, 10);
        assert_eq!(selected.status, "in_progress");
    }

    #[test]
    fn numeric_latest_run_wins_over_unordered_old_success() {
        let mut latest = HashMap::new();
        let batch = task_id_for(1);
        let mut older = run_state_with_id(9, "completed", Some("success"), true);
        older.task_id = batch.clone();
        let mut newer = run_state_with_id(10, "in_progress", None, true);
        newer.task_id = batch.clone();
        retain_latest_run(&mut latest, older, None);
        retain_latest_run(&mut latest, newer, None);
        let selected = latest.remove(&batch).expect("latest run");
        assert_eq!(selected.workflow_run_id, 10);
        assert_eq!(selected.status, "in_progress");
    }

    #[test]
    fn returned_run_id_rejects_old_visibility_until_new_run_appears() {
        let mut latest = HashMap::new();
        retain_latest_run(
            &mut latest,
            run_state_with_id(9, "completed", Some("success"), true),
            Some(10),
        );
        assert!(latest.is_empty());
    }

    /// A bound-run GET must answer for the exact id the batch tracks —
    /// another run's row is never this batch's state, so the binding
    /// is refused rather than replaced.
    #[test]
    fn a_bound_poll_never_takes_another_run_id() {
        let rustc = WireRustcVersion::parse("1.99.0").expect("rustc");
        let row = run_row(
            11,
            &format!("1.99.0-{}", task_id_for(10)),
            "completed",
            Some("success"),
        );
        assert!(bound_run_state(row, 10, &task_id_for(10), &rustc).is_err());
    }

    /// The bound id's title must be `<rustc>-b<task_id>` — a row for
    /// a different batch, a different rustc, or no batch title at all
    /// is a hard error, not a fold.
    #[test]
    fn a_bound_poll_validates_the_run_title() {
        let rustc = WireRustcVersion::parse("1.99.0").expect("rustc");
        let batch = task_id_for(10);
        let title = format!("1.99.0-{batch}");
        let state = bound_run_state(
            run_row(10, &title, "completed", Some("success")),
            10,
            &batch,
            &rustc,
        );
        assert!(matches!(state, Ok(Some(_))));
        assert!(
            bound_run_state(
                run_row(
                    10,
                    &format!("1.99.0-{}", task_id_for(11)),
                    "completed",
                    Some("success")
                ),
                10,
                &batch,
                &rustc
            )
            .is_err()
        );
        assert!(
            bound_run_state(
                run_row(10, &format!("1.98.0-{batch}"), "completed", Some("success")),
                10,
                &batch,
                &rustc
            )
            .is_err()
        );
        assert!(
            bound_run_state(
                run_row(10, "untitled-run", "completed", Some("success")),
                10,
                &batch,
                &rustc
            )
            .is_err()
        );
    }

    /// stow#704 at batch scope: until GitHub renders a run's
    /// `run-name`, its `display_title` is `build-crate.yml`'s `name:` —
    /// a title pending, `Ok(None)`, not a state and not another
    /// workflow's run. The id check still comes first.
    #[test]
    fn an_untitled_bound_run_is_not_a_state() {
        let rustc = WireRustcVersion::parse("1.99.0").expect("rustc");
        let batch = task_id_for(10);
        assert!(matches!(
            bound_run_state(
                run_row(10, WORKFLOW_NAME, "queued", None),
                10,
                &batch,
                &rustc
            ),
            Ok(None)
        ));
        assert!(
            bound_run_state(
                run_row(10, WORKFLOW_NAME, "queued", None),
                11,
                &batch,
                &rustc
            )
            .is_err()
        );
    }

    /// Mixed fold outcomes across one poll: a completed success marks
    /// every covered leg done, a completed failure on current code
    /// folds the local lane's leg rows — the failed leg's node fails —
    /// an in-flight run binds and stays open, and a failure on moved
    /// `main` code unbinds the batch's nodes for redispatch.
    #[tokio::test]
    async fn a_poll_folds_each_bound_run_by_its_outcome() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) = build_graph(vec![
            request("won", T, false, &[]),
            request("lost", T, false, &[]),
            request("flying", T, false, &[]),
            request("stale", T, false, &[]),
        ])
        .expect("valid graph");
        let ids: BTreeMap<&str, String> = ["won", "lost", "flying", "stale"]
            .into_iter()
            .map(|name| {
                (
                    name,
                    node_task_id(request_by_name(name, &nodes)).expect("task id"),
                )
            })
            .collect();
        let mut open: BTreeSet<String> = nodes.keys().cloned().collect();
        let mut runs = HashMap::new();
        for (name, run_id) in [("won", 100), ("lost", 101), ("flying", 102)] {
            runs.insert(ids[name].clone(), bound_run(&ids[name], run_id));
        }
        runs.insert(ids["stale"].clone(), bound_run(&ids["stale"], 50));
        for (name, run_id) in [("won", 100), ("lost", 101), ("flying", 102), ("stale", 50)] {
            let node = nodes.get_mut(&ids[name]).expect("bound node");
            node.workflow_run_id = Some(run_id);
            node.dispatched = true;
        }
        let dispatch = local_dispatch("http://localhost");
        let mut reruns = Vec::new();
        let mut gate = WriteGate::new();
        {
            let mut wave = wave(&mut nodes, &mut open, &mut runs, &mut reruns, &mut gate);
            let mut won_state = run_state_with_id(100, "completed", Some("success"), true);
            won_state.task_id = ids["won"].clone();
            classify_and_fold(&dispatch, won_state, &mut wave, MAIN_HEAD)
                .await
                .expect("the successful run folds");
            let mut lost = run_state_with_id(101, "completed", Some("failure"), true);
            lost.task_id = ids["lost"].clone();
            lost.error = Some("the build failed".to_owned());
            classify_and_fold(&dispatch, lost, &mut wave, MAIN_HEAD)
                .await
                .expect("the failed run folds");
            let mut flying = run_state_with_id(102, "in_progress", None, true);
            flying.task_id = ids["flying"].clone();
            classify_and_fold(&dispatch, flying, &mut wave, MAIN_HEAD)
                .await
                .expect("the in-flight run binds");
            let mut stale = run_state_with_id(50, "completed", Some("failure"), false);
            stale.task_id = ids["stale"].clone();
            classify_and_fold(&dispatch, stale, &mut wave, MAIN_HEAD)
                .await
                .expect("the stale run releases");
        }

        let won = &ids["won"];
        let lost = &ids["lost"];
        let flying = &ids["flying"];
        assert!(nodes[won].done && !open.contains(won));
        assert!(nodes[lost].failed && !open.contains(lost));
        assert!(!nodes[flying].done && !nodes[flying].failed && nodes[flying].dispatched);
        assert_eq!(nodes[flying].workflow_run_id, Some(102));

        // The stale node: its bound run failed on code `main` moved
        // past — the binding drops and the node can dispatch again.
        let stale = &ids["stale"];
        let node = &nodes[stale];
        assert!(
            node.workflow_run_id.is_none() && node.run_url.is_none() && !node.dispatched,
            "the stale run's node returns to unsent"
        );
        assert!(open.contains(stale));
        assert!(!runs.contains_key(&ids["stale"]));
    }

    /// A stale row for a different run id of the same batch never
    /// releases the node — release matches the bound run id.
    #[tokio::test]
    async fn only_the_bound_run_id_releases_on_stale() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) =
            build_graph(vec![request("bound", T, false, &[])]).expect("valid graph");
        let task = node_task_id(request_by_name("bound", &nodes)).expect("task id");
        let mut open: BTreeSet<String> = nodes.keys().cloned().collect();
        nodes.get_mut(&task).expect("node").workflow_run_id = Some(50);
        nodes.get_mut(&task).expect("node").dispatched = true;
        let mut runs = HashMap::from([(task.clone(), bound_run(&task, 50))]);
        let mut other = run_state_with_id(99, "completed", Some("failure"), false);
        other.task_id = task.clone();
        let dispatch = local_dispatch("http://localhost");
        let mut reruns = Vec::new();
        let mut gate = WriteGate::new();
        {
            let mut wave = wave(&mut nodes, &mut open, &mut runs, &mut reruns, &mut gate);
            classify_and_fold(&dispatch, other, &mut wave, MAIN_HEAD)
                .await
                .expect("fold");
        }
        assert_eq!(nodes[&task].workflow_run_id, Some(50));
        assert!(nodes[&task].dispatched);
    }

    /// The tracked-id filter every poll and adoption applies through
    /// `retain_latest_run`: an old same-batch completion cannot answer
    /// a newer bound retry — it drops before the fold, while the bound
    /// id itself lands.
    #[test]
    fn an_old_same_batch_completion_cannot_answer_a_bound_retry() {
        let mut latest = HashMap::new();
        let batch = task_id_for(50);
        let mut old = run_state_with_id(40, "completed", Some("success"), true);
        old.task_id = batch.clone();
        retain_latest_run(&mut latest, old, Some(50));
        assert!(latest.is_empty(), "untracked id dropped before the fold");

        let bound = run_state_with_id(50, "completed", Some("success"), true);
        retain_latest_run(&mut latest, bound, Some(50));
        assert_eq!(latest[&batch].workflow_run_id, 50);
    }

    /// At `MAX_RUN_ATTEMPTS` an infrastructure leg fails with the rest
    /// — nothing earns a rerun past the bound.
    #[test]
    fn infrastructure_at_max_attempts_is_final() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) =
            build_graph(vec![request("flake", T, false, &[])]).expect("valid graph");
        let task = node_task_id(request_by_name("flake", &nodes)).expect("task id");
        let mut open: BTreeSet<String> = nodes.keys().cloned().collect();
        nodes.get_mut(&task).expect("node").workflow_run_id = Some(50);
        let batch = bound_run(&task, 50);
        let outcome = TaskOutcome::Failed(TaskFailure::Run(RunFailure::Infrastructure {
            job: format!("leg 0 / build #0 flake 1.0.0 ({T}) {}", TaskHash::of(&task)),
            step: Some("Set up runner".to_owned()),
            html_url: "https://github.com/water-rs/stow/actions/runs/50/job/1".to_owned(),
        }));
        let earners = fold_run_outcome(&outcome, &batch, 50, true, &mut nodes, &mut open);
        assert!(
            earners.is_none(),
            "at MAX_RUN_ATTEMPTS nothing earns a rerun"
        );
        assert!(nodes[&task].failed && !open.contains(&task));
    }

    /// The local CI server has no runner setup: a failure is always
    /// the verdict, at any attempt — even at `MAX_RUN_ATTEMPTS` no
    /// rerun is asked.
    #[tokio::test]
    async fn the_local_lane_takes_every_failure_as_final() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) =
            build_graph(vec![request("task", T, false, &[])]).expect("valid graph");
        let task = node_task_id(request_by_name("task", &nodes)).expect("task id");
        let mut open: BTreeSet<String> = nodes.keys().cloned().collect();
        let mut runs = HashMap::from([(task.clone(), bound_run(&task, 50))]);
        let mut state = run_state_with_id(50, "completed", Some("failure"), true);
        state.task_id = task.clone();
        state.run_attempt = MAX_RUN_ATTEMPTS;
        state.error = Some("the build failed".to_owned());
        let dispatch = local_dispatch("http://localhost");
        let mut reruns = Vec::new();
        let mut gate = WriteGate::new();
        {
            let mut wave = wave(&mut nodes, &mut open, &mut runs, &mut reruns, &mut gate);
            classify_and_fold(&dispatch, state, &mut wave, MAIN_HEAD)
                .await
                .expect("fold");
        }
        assert!(nodes[&task].failed && !open.contains(&task));
        assert!(reruns.is_empty(), "the local lane never asks a rerun");
    }

    /// A rerun keeps the batch's leg open and bound to the same run —
    /// the failed attempt's cached row and validator drop so the next
    /// poll reads the rerun's own state.
    #[test]
    fn a_rerun_stays_open_bound_to_the_same_run() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) =
            build_graph(vec![request("flake", T, false, &[])]).expect("valid graph");
        let task = node_task_id(request_by_name("flake", &nodes)).expect("task id");
        let mut open: BTreeSet<String> = nodes.keys().cloned().collect();
        {
            let node = nodes.get_mut(&task).expect("node");
            node.workflow_run_id = Some(77);
            node.dispatched = true;
        }
        let mut runs = HashMap::from([(task.clone(), bound_run(&task, 77))]);
        {
            let batch = runs.get_mut(&task).expect("batch");
            batch.etag = Some("etag".to_owned());
            batch.latest = Some(run_state_with_id(77, "in_progress", None, true));
        }
        let outcome = TaskOutcome::Failed(TaskFailure::Run(RunFailure::Infrastructure {
            job: format!("leg 0 / build #0 flake 1.0.0 ({T}) {}", TaskHash::of(&task)),
            step: Some("Run dtolnay/rust-toolchain".to_owned()),
            html_url: "https://github.com/water-rs/stow/actions/runs/77/job/1".to_owned(),
        }));
        let earners = {
            let batch = runs.get(&task).expect("batch");
            fold_run_outcome(&outcome, batch, 77, false, &mut nodes, &mut open)
        };
        let earner = earners.expect("a rerun earner");
        let state = run_state_with_id(77, "completed", Some("failure"), true);
        let mut reruns = Vec::new();
        let mut gate = WriteGate::new();
        {
            let mut wave = wave(&mut nodes, &mut open, &mut runs, &mut reruns, &mut gate);
            apply_rerun_answer(&task, &state, earner, Ok(()), &mut wave)
                .expect("a confirmed rerun applies");
        }
        let node = &nodes[&task];
        assert!(open.contains(&task) && !node.failed && !node.done);
        assert_eq!(node.workflow_run_id, Some(77));
        assert!(node.dispatched);
        let batch = &runs[&task];
        assert!(batch.etag.is_none() && batch.latest.is_none());
        assert_eq!(reruns.len(), 1);
        assert_eq!(reruns[0].run_attempt, 2);
    }

    /// An ambiguous `rerun-failed-jobs` answer keeps the ask pending:
    /// the batch's leg stays open and bound while the next row answers
    /// whether the run took the rerun.
    #[test]
    fn an_unanswered_rerun_keeps_the_batch_open() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) =
            build_graph(vec![request("adopted", T, false, &[])]).expect("valid graph");
        let task = node_task_id(request_by_name("adopted", &nodes)).expect("task id");
        let mut open: BTreeSet<String> = nodes.keys().cloned().collect();
        {
            let node = nodes.get_mut(&task).expect("node");
            node.workflow_run_id = Some(88);
            node.dispatched = true;
        }
        let mut runs = HashMap::from([(task.clone(), bound_run(&task, 88))]);
        let outcome = TaskOutcome::Failed(TaskFailure::Run(RunFailure::Infrastructure {
            job: "-".to_owned(),
            step: None,
            html_url: String::new(),
        }));
        let earners = {
            let batch = runs.get(&task).expect("batch");
            fold_run_outcome(&outcome, batch, 88, false, &mut nodes, &mut open)
        };
        let earner = earners.expect("a rerun earner");
        let state = run_state_with_id(88, "completed", Some("failure"), true);
        let mut reruns = Vec::new();
        let mut gate = WriteGate::new();
        {
            let mut wave = wave(&mut nodes, &mut open, &mut runs, &mut reruns, &mut gate);
            apply_rerun_answer(
                &task,
                &state,
                earner,
                Err(WriteFailure::Ambiguous("timeout".to_owned())),
                &mut wave,
            )
            .expect("an ambiguous answer holds the gate, not an error");
        }
        let node = &nodes[&task];
        assert!(open.contains(&task) && !node.failed && node.dispatched);
        assert_eq!(node.workflow_run_id, Some(88));
        assert!(
            runs[&task].pending_rerun.is_some(),
            "the unanswered ask rides the batch until a row answers it"
        );
    }

    /// A verdict stays final: the fold marks the leg's node failed and
    /// the dependent layer is skipped behind it — unchanged from
    /// before the rerun rule.
    #[test]
    fn a_final_failure_fails_the_node_and_blocks_dependents() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let mid = request("mid", T, false, &[("leaf", T, false)]);
        let (mut nodes, edges) =
            build_graph(vec![request("leaf", T, false, &[]), mid]).expect("valid graph");
        let ids = |name: &str| node_task_id(request_by_name(name, &nodes)).expect("task id");
        let (leaf, mid) = (ids("leaf"), ids("mid"));
        let mut open: BTreeSet<String> = nodes.keys().cloned().collect();
        nodes.get_mut(&leaf).expect("node").workflow_run_id = Some(90);
        let batch = bound_run(&leaf, 90);
        let outcome = TaskOutcome::Failed(TaskFailure::Run(RunFailure::Verdict {
            job: format!("leg 0 / build #0 leaf 1.0.0 ({T}) {}", TaskHash::of(&leaf)),
            step: "cargo build".to_owned(),
            html_url: "https://github.com/water-rs/stow/actions/runs/90/job/1".to_owned(),
        }));
        let earners = fold_run_outcome(&outcome, &batch, 90, false, &mut nodes, &mut open);
        assert!(earners.is_none(), "a verdict never earns a rerun");
        assert!(nodes[&leaf].failed && !open.contains(&leaf));
        let blocked = mark_blocked(std::slice::from_ref(&mid), &mut nodes, &edges);
        assert_eq!(blocked, vec![(mid.clone(), leaf)]);
    }

    /// The local lane's `GET /tasks` poll rides the shared bounded
    /// idempotent read: a server-side connection drop is retried rather
    /// than ending the wave, and the unauthenticated request carries no
    /// `Authorization` header — no credential leaves the machine.
    #[tokio::test]
    async fn local_list_runs_recovers_a_dropped_connection() {
        let server = crate::test_server::Loopback::start(vec![
            crate::test_server::Step::Drop,
            crate::test_server::Step::Respond {
                status: 200,
                retry_after: None,
                body: r#"{"tasks":[{"workflow_run_id":7,"display_title":"1.99.0-taskabc","status":"completed","conclusion":"success","html_url":"http://localhost/run/7","path":".github/workflows/build-crate.yml","dispatched_at_ms":0,"completed_at_ms":0,"error":null,"delivery_errors":[],"task_id":"taskabc"}]}"#,
            },
        ])
        .await;
        let rustc = WireRustcVersion::parse("1.99.0").expect("rustc version parses");
        let runs = local_run_states(&server.url, &rustc)
            .await
            .expect("a dropped connection retries");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].task_id, "taskabc");
        assert_eq!(runs[0].workflow_run_id, 7);
        assert_eq!(runs[0].task_id, "taskabc");
        assert_eq!(runs[0].conclusion.as_deref(), Some("success"));
        let heads = server.join().await;
        assert_eq!(heads.len(), 2);
        for request in &heads {
            assert!(
                !request
                    .head
                    .headers
                    .contains_key(http::header::AUTHORIZATION),
                "the local read must not send an Authorization header: {:?}",
                request.head.headers
            );
        }
    }

    /// stow#647 at batch scope: an ambiguous dispatch binds through
    /// the resolution listing — only a run created at or after the
    /// attempt (minus [`GITHUB_CLOCK_ALLOWANCE`]) may answer it, and
    /// the newest of the qualifying runs is the one that binds.
    #[tokio::test]
    async fn an_unresolved_run_binds_the_newest_qualifying_run() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) =
            build_graph(vec![request("task", T, false, &[])]).expect("valid graph");
        let task = node_task_id(request_by_name("task", &nodes)).expect("task id");
        let mut open: BTreeSet<String> = nodes.keys().cloned().collect();
        let mut runs = HashMap::new();
        let batch = task.clone();
        unresolved_run(&mut runs, &mut nodes, &task, 9, at(1_000_000));
        let state = |run_id: u64, created_unix: i64| {
            let mut state = run_state_with_id(run_id, "in_progress", None, true);
            state.task_id = task.clone();
            state.task_id = batch.clone();
            state.created_at = Some(at(created_unix));
            state
        };
        let mut latest = HashMap::new();
        retain_qualifying_runs(
            &mut latest,
            vec![
                // Created before the attempt's floor — it can never be
                // this attempt's answer.
                state(7, 1_000_000 - 61),
                // Exactly at the floor — qualifies.
                state(8, 1_000_000 - 60),
                // The newest qualifying run binds.
                state(9, 1_000_000 + 5),
            ],
            &runs,
        );
        let selected = latest.remove(&batch).expect("a qualifying run");
        assert_eq!(selected.workflow_run_id, 9);

        let dispatch = local_dispatch("http://localhost");
        let mut gate = WriteGate::new();
        let mut reruns = Vec::new();
        {
            let mut wave = wave(&mut nodes, &mut open, &mut runs, &mut reruns, &mut gate);
            classify_and_fold(&dispatch, selected, &mut wave, MAIN_HEAD)
                .await
                .expect("fold");
        }
        let node = &nodes[&task];
        assert_eq!(node.workflow_run_id, Some(9));
        assert!(node.dispatched);
        assert!(runs[&batch].unresolved.is_none());
    }

    /// An attempt the listing never answers — GitHub never took the
    /// write — returns to unsent once the grace expires, so the next
    /// dispatch pass sends it again.
    #[tokio::test(start_paused = true)]
    async fn an_unresolved_run_past_the_grace_returns_to_unsent() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) =
            build_graph(vec![request("task", T, false, &[])]).expect("valid graph");
        let task = node_task_id(request_by_name("task", &nodes)).expect("task id");
        let mut open: BTreeSet<String> = nodes.keys().cloned().collect();
        let mut runs = HashMap::new();
        let batch = task.clone();
        unresolved_run(&mut runs, &mut nodes, &task, 9, at(1_000_000));
        // The listing answers nothing for the run — an empty mock CI.
        let server = MockCi::start(&[], &[], "1.99.0").await;
        let dispatch = local_dispatch(&server.url);
        let rustc = WireRustcVersion::parse("1.99.0").expect("rustc");
        let mut gate = WriteGate::new();
        let mut reruns = Vec::new();
        {
            let mut wave = wave(&mut nodes, &mut open, &mut runs, &mut reruns, &mut gate);
            // Inside the grace the attempt stays unresolved.
            resolve_unanswered(&dispatch, &mut wave, MAIN_HEAD, &rustc)
                .await
                .expect("resolve");
            assert!(wave.runs[&batch].unresolved.is_some() && wave.nodes[&task].dispatched);
            // Past it, the batch drops and the node returns to unsent.
            tokio::time::advance(std::time::Duration::from_secs(60 * RUN_GRACE_MINUTES + 60)).await;
            resolve_unanswered(&dispatch, &mut wave, MAIN_HEAD, &rustc)
                .await
                .expect("resolve");
        }
        assert!(runs.is_empty());
        assert!(!nodes[&task].dispatched);
        server.shutdown().await;
    }

    /// The `overdue` check names confirmed dispatches whose run never
    /// materialized — an unresolved batch carries no confirmed id and
    /// can never be overdue.
    #[test]
    fn the_overdue_check_never_fires_for_an_unresolved_run() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) =
            build_graph(vec![request("task", T, false, &[])]).expect("valid graph");
        let task = node_task_id(request_by_name("task", &nodes)).expect("task id");
        let mut runs = HashMap::new();
        let batch = task.clone();
        unresolved_run(&mut runs, &mut nodes, &task, 9, at(1_000_000));
        assert!(!dispatch_overdue(&runs[&batch]));
        // A confirmed send's unmaterialized run still fires past the
        // grace — the check itself is unchanged.
        {
            let entry = runs.get_mut(&batch).expect("batch");
            entry.unresolved = None;
            entry.workflow_run_id = Some(9);
            entry.observed = false;
            entry.dispatched_at = Some(
                std::time::Instant::now()
                    .checked_sub(std::time::Duration::from_secs(60 * RUN_GRACE_MINUTES + 60))
                    .expect("the host has been up longer than the grace"),
            );
        }
        assert!(dispatch_overdue(&runs[&batch]));
    }

    /// The progress counts partition the layer: done, failed, blocked,
    /// unresolved-dispatch, queued-run and in-progress-run nodes each
    /// land in their own count — `running_batches` names only the legs
    /// riding a bound run GitHub still reports in progress — and the
    /// buckets sum to the layer. The settled nodes keep `dispatched`
    /// set, exactly as the folds leave them, so the `dispatched`
    /// count's `!done && !failed` guard is exercised.
    #[test]
    fn the_layer_progress_counts_partition_the_layer() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) = build_graph(vec![
            request("done", T, false, &[]),
            request("failed", T, false, &[]),
            request("blocked", T, false, &[]),
            request("unresolved", T, false, &[]),
            request("queued", T, false, &[]),
            request("running", T, false, &[]),
            request("waiting", T, false, &[]),
        ])
        .expect("valid graph");
        let ids: BTreeMap<&str, String> = [
            "done",
            "failed",
            "blocked",
            "unresolved",
            "queued",
            "running",
            "waiting",
        ]
        .into_iter()
        .map(|name| {
            (
                name,
                node_task_id(request_by_name(name, &nodes)).expect("task id"),
            )
        })
        .collect();
        let layer: Vec<String> = nodes.keys().cloned().collect();
        // A settled node keeps `dispatched` and its run binding — the
        // folds only flip `done`/`failed` and drop it from `open`.
        {
            let node = nodes.get_mut(&ids["done"]).expect("done node");
            node.done = true;
            node.dispatched = true;
            node.workflow_run_id = Some(40);
        }
        {
            let node = nodes.get_mut(&ids["failed"]).expect("failed node");
            node.failed = true;
            node.dispatched = true;
            node.workflow_run_id = Some(41);
        }
        nodes
            .get_mut(&ids["blocked"])
            .expect("blocked node")
            .blocked_by = Some(ids["failed"].clone());
        let mut runs = HashMap::new();
        unresolved_run(&mut runs, &mut nodes, &ids["unresolved"], 9, at(1_000_000));
        for (name, run_id, status) in [("queued", 50, "queued"), ("running", 51, "in_progress")] {
            {
                let node = nodes.get_mut(&ids[name]).expect("bound node");
                node.dispatched = true;
                node.workflow_run_id = Some(run_id);
            }
            let mut batch = bound_run(&ids[name], run_id);
            batch.latest = Some(run_state_with_id(run_id, status, None, true));
            runs.insert(ids[name].clone(), batch);
        }
        let progress = layer_progress(&layer, &nodes, &runs);
        assert_eq!(
            progress,
            LayerProgress {
                total: 7,
                done: 1,
                failed: 1,
                skipped: 1,
                dispatched: 3,
                running: 1,
                remaining: 1,
            }
        );
        assert_eq!(
            progress.done
                + progress.failed
                + progress.skipped
                + progress.dispatched
                + progress.remaining,
            progress.total,
            "the counts partition the layer"
        );
    }

    /// stow#647 section D at batch scope: a rerun asked on attempt N
    /// is accepted once the run shows a later attempt — the record the
    /// confirmed path would have pushed lands, and the new row folds
    /// as usual.
    #[tokio::test]
    async fn a_later_attempt_settles_an_asked_rerun() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) =
            build_graph(vec![request("task", T, false, &[])]).expect("valid graph");
        let task = node_task_id(request_by_name("task", &nodes)).expect("task id");
        let mut open: BTreeSet<String> = nodes.keys().cloned().collect();
        {
            let node = nodes.get_mut(&task).expect("node");
            node.dispatched = true;
            node.workflow_run_id = Some(50);
        }
        let mut runs = HashMap::from([(task.clone(), bound_run(&task, 50))]);
        runs.get_mut(&task).expect("batch").pending_rerun = Some(PendingRerun {
            attempt: 1,
            asked_at: tokio::time::Instant::now(),
            task: RerunTask {
                task_id: task.clone(),
                job: "build".to_owned(),
                step: Some("setup".to_owned()),
            },
        });
        let mut state = run_state_with_id(50, "in_progress", None, true);
        state.task_id = task.clone();
        state.run_attempt = 2;
        let dispatch = local_dispatch("http://localhost");
        let mut gate = WriteGate::new();
        let mut reruns = Vec::new();
        {
            let mut wave = wave(&mut nodes, &mut open, &mut runs, &mut reruns, &mut gate);
            classify_and_fold(&dispatch, state, &mut wave, MAIN_HEAD)
                .await
                .expect("fold");
        }
        assert_eq!(reruns.len(), 1);
        assert_eq!(reruns[0].task_id, task);
        assert_eq!(reruns[0].job, "build");
        assert_eq!(reruns[0].step.as_deref(), Some("setup"));
        assert_eq!(reruns[0].run_attempt, 2);
        let node = &nodes[&task];
        assert!(open.contains(&task) && !node.failed);
        assert!(runs[&task].pending_rerun.is_none());
    }

    /// The same completed attempt inside the grace is no answer — the
    /// row classifies nothing and the batch keeps waiting.
    #[tokio::test]
    async fn a_same_attempt_row_inside_the_grace_waits() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) =
            build_graph(vec![request("task", T, false, &[])]).expect("valid graph");
        let task = node_task_id(request_by_name("task", &nodes)).expect("task id");
        let mut open: BTreeSet<String> = nodes.keys().cloned().collect();
        {
            let node = nodes.get_mut(&task).expect("node");
            node.dispatched = true;
            node.workflow_run_id = Some(50);
        }
        let mut runs = HashMap::from([(task.clone(), bound_run(&task, 50))]);
        runs.get_mut(&task).expect("batch").pending_rerun = Some(PendingRerun {
            attempt: 1,
            asked_at: tokio::time::Instant::now(),
            task: RerunTask {
                task_id: task.clone(),
                job: "build".to_owned(),
                step: None,
            },
        });
        let mut state = run_state_with_id(50, "completed", Some("failure"), true);
        state.task_id = task.clone();
        state.run_attempt = 1;
        let dispatch = local_dispatch("http://localhost");
        let mut gate = WriteGate::new();
        let mut reruns = Vec::new();
        {
            let mut wave = wave(&mut nodes, &mut open, &mut runs, &mut reruns, &mut gate);
            classify_and_fold(&dispatch, state, &mut wave, MAIN_HEAD)
                .await
                .expect("fold");
        }
        let node = &nodes[&task];
        assert!(runs[&task].pending_rerun.is_some());
        assert!(!node.failed && open.contains(&task));
        assert!(reruns.is_empty());
    }

    /// The same completed attempt past the grace drops the pending
    /// record and classifies the row again — the local lane's classify
    /// is always the verdict, so the fold lands the failure.
    #[tokio::test(start_paused = true)]
    async fn a_same_attempt_row_past_the_grace_classifies_again() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) =
            build_graph(vec![request("task", T, false, &[])]).expect("valid graph");
        let task = node_task_id(request_by_name("task", &nodes)).expect("task id");
        let mut open: BTreeSet<String> = nodes.keys().cloned().collect();
        {
            let node = nodes.get_mut(&task).expect("node");
            node.dispatched = true;
            node.workflow_run_id = Some(50);
        }
        let mut runs = HashMap::from([(task.clone(), bound_run(&task, 50))]);
        runs.get_mut(&task).expect("batch").pending_rerun = Some(PendingRerun {
            attempt: 1,
            asked_at: tokio::time::Instant::now(),
            task: RerunTask {
                task_id: task.clone(),
                job: "build".to_owned(),
                step: None,
            },
        });
        // The ask is now older than the grace.
        tokio::time::advance(std::time::Duration::from_secs(60 * RUN_GRACE_MINUTES + 60)).await;
        let mut state = run_state_with_id(50, "completed", Some("failure"), true);
        state.task_id = task.clone();
        state.run_attempt = 1;
        state.error = Some("the build failed".to_owned());
        let dispatch = local_dispatch("http://localhost");
        let mut gate = WriteGate::new();
        let mut reruns = Vec::new();
        {
            let mut wave = wave(&mut nodes, &mut open, &mut runs, &mut reruns, &mut gate);
            classify_and_fold(&dispatch, state, &mut wave, MAIN_HEAD)
                .await
                .expect("fold");
        }
        let node = &nodes[&task];
        assert!(
            !runs.contains_key(&task),
            "the settled run's batch frees its slots"
        );
        assert!(node.failed && !open.contains(&task));
    }

    /// A run whose task hit infrastructure earns the rerun — the
    /// node stays open and bound while a confirmed answer applies
    /// its ask.
    #[test]
    fn an_infrastructure_failure_earns_a_rerun() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) =
            build_graph(vec![request("flake", T, false, &[])]).expect("valid graph");
        let task = node_task_id(request_by_name("flake", &nodes)).expect("task id");
        let mut open: BTreeSet<String> = nodes.keys().cloned().collect();
        nodes.get_mut(&task).expect("node").workflow_run_id = Some(50);
        nodes.get_mut(&task).expect("node").dispatched = true;
        let batch = bound_run(&task, 50);
        let jobs = vec![
            job_row(
                &format!("build flake 1.0.0 ({T})"),
                "completed",
                Some("failure"),
                &[
                    ("Set up runner", "completed", Some("failure")),
                    ("Build", "completed", Some("skipped")),
                ],
            ),
            job_row("publish", "completed", Some("skipped"), &[]),
        ];
        let outcome = classify_page(&jobs, "failure", at(120)).expect("classified");
        assert!(
            matches!(
                outcome,
                TaskOutcome::Failed(TaskFailure::Run(RunFailure::Infrastructure { .. }))
            ),
            "the task is the infrastructure failure: {outcome:?}"
        );
        let earners = fold_run_outcome(&outcome, &batch, 50, false, &mut nodes, &mut open);
        let earner = earners.expect("the failed task earns the rerun");
        assert_eq!(earner.task_id, task);
        assert!(
            open.contains(&task) && !nodes[&task].failed,
            "the infrastructure task stays open for its rerun"
        );
        let mut runs = HashMap::from([(task.clone(), batch)]);
        let state = run_state_with_id(50, "completed", Some("failure"), true);
        let mut reruns = Vec::new();
        let mut gate = WriteGate::new();
        {
            let mut wave = wave(&mut nodes, &mut open, &mut runs, &mut reruns, &mut gate);
            apply_rerun_answer(&task, &state, earner, Ok(()), &mut wave)
                .expect("a confirmed rerun applies");
        }
        assert_eq!(reruns.len(), 1);
        assert_eq!(reruns[0].task_id, task);
        assert_eq!(nodes[&task].workflow_run_id, Some(50));
    }

    /// The in-test local CI server `Dispatch::Local` drives: it
    /// records every `/dispatch` it is scripted to take, answers the
    /// scripted 500s — one after recording the batch, one without —
    /// and serves the recorded runs on `GET /tasks` as batch runs with
    /// leg rows, the same shape `stow-build serve` speaks.
    struct MockCi {
        url: String,
        state: std::sync::Arc<std::sync::Mutex<MockCiState>>,
        task: Option<tokio::task::JoinHandle<()>>,
    }

    #[derive(Default)]
    struct MockCiState {
        /// `(task_id, run_id)` per recorded dispatch, in order.
        recorded: Vec<(String, u64)>,
        /// The task id of every `/dispatch` the server saw —
        /// including the ones it answered 500.
        seen: Vec<String>,
        /// Crate names whose next dispatch records then answers 500.
        ghost: BTreeSet<String>,
        /// Crate names whose next dispatch answers 500 unrecorded.
        unrecorded: BTreeSet<String>,
        next_id: u64,
        rustc: String,
    }

    /// `GET /tasks` of the mock CI: every recorded dispatch as a
    /// completed batch run, the same shape `stow-build serve` speaks.
    async fn mock_tasks(
        axum::extract::State(state): axum::extract::State<
            std::sync::Arc<std::sync::Mutex<MockCiState>>,
        >,
    ) -> axum::Json<serde_json::Value> {
        let tasks: Vec<serde_json::Value> = {
            let state = state.lock().expect("mock state");
            state
                .recorded
                .iter()
                .map(|(task_id, run_id)| {
                    serde_json::json!({
                        "workflow_run_id": run_id,
                        "display_title": format!("{}-{}", state.rustc, task_id),
                        "path": format!(
                            ".github/workflows/{}",
                            stow_types::trusted_builder::WORKFLOW_FILE
                        ),
                        "status": "completed",
                        "conclusion": "success",
                        "html_url": format!("http://localhost/run/{run_id}"),
                        "dispatched_at_ms": 0,
                        "completed_at_ms": 0,
                        "error": null,
                        "delivery_errors": [],
                        "task_id": task_id,
                    })
                })
                .collect()
        };
        axum::Json(serde_json::json!({ "tasks": tasks }))
    }

    impl MockCi {
        /// `ghost` dispatches record then fail; `unrecorded` fail
        /// without recording — each once, on the first matching send,
        /// keyed by the batch's first leg's crate name.
        async fn start(ghost: &[&str], unrecorded: &[&str], rustc: &str) -> Self {
            use axum::response::IntoResponse as _;
            let state = std::sync::Arc::new(std::sync::Mutex::new(MockCiState {
                ghost: ghost.iter().map(|name| (*name).to_owned()).collect(),
                unrecorded: unrecorded.iter().map(|name| (*name).to_owned()).collect(),
                next_id: 1,
                rustc: rustc.to_owned(),
                ..MockCiState::default()
            }));
            let shared = state.clone();
            let app = axum::Router::new()
                .route(
                    "/dispatch",
                    axum::routing::post(
                        |axum::extract::State(state): axum::extract::State<
                            std::sync::Arc<std::sync::Mutex<MockCiState>>,
                        >,
                         body: axum::body::Bytes| async move {
                            let body: serde_json::Value =
                                serde_json::from_slice(&body).expect("dispatch body");
                            let payload = &body["client_payload"];
                            let task_id = payload["task_id"].as_str().expect("task_id").to_owned();
                            let crate_name = payload["crate_name"]
                                .as_str()
                                .expect("crate_name")
                                .to_owned();
                            let mut state = state.lock().expect("mock state");
                            state.seen.push(task_id.clone());
                            let run_id = state.next_id;
                            state.next_id += 1;
                            let fail = if state.ghost.remove(&crate_name) {
                                state.recorded.push((task_id, run_id));
                                true
                            } else if state.unrecorded.remove(&crate_name) {
                                true
                            } else {
                                state.recorded.push((task_id, run_id));
                                false
                            };
                            drop(state);
                            if fail {
                                return axum::http::StatusCode::INTERNAL_SERVER_ERROR
                                    .into_response();
                            }
                            axum::Json(serde_json::json!({ "workflow_run_id": run_id }))
                                .into_response()
                        },
                    ),
                )
                .route("/tasks", axum::routing::get(mock_tasks))
                // `Dispatch::status()` asks the GitHub-shaped
                // workflow-runs listing (stow#877); the mock completes
                // every recorded run instantly, so queued and
                // in-progress are always empty.
                .route(
                    "/repos/water-rs/stow/actions/workflows/build-crate.yml/runs",
                    axum::routing::get(|| async {
                        axum::Json(serde_json::json!({
                            "total_count": 0,
                            "workflow_runs": [],
                        }))
                    }),
                )
                .with_state(shared);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind mock ci");
            let addr = listener.local_addr().expect("local addr");
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.expect("mock ci serves");
            });
            Self {
                url: format!("http://{addr}"),
                state,
                task: Some(task),
            }
        }

        /// Stop the server — the panic-path cleanup is `Drop`'s abort.
        async fn shutdown(mut self) {
            if let Some(task) = self.task.take() {
                task.abort();
                let _ = task.await;
            }
        }
    }

    impl Drop for MockCi {
        fn drop(&mut self) {
            if let Some(task) = self.task.take() {
                task.abort();
            }
        }
    }

    /// stow#647 end to end: the wave survives ambiguous dispatch
    /// answers — a 500 that recorded the run resolves through the
    /// listing, a 500 that recorded nothing re-sends after the grace,
    /// and every node finishes with each task dispatched exactly once.
    /// Virtual time makes the ten-minute grace and the backoff waits
    /// free. The bound is a real-time watchdog thread, not a tokio
    /// timer: under the paused clock every virtual deadline fires at
    /// the first park for real I/O, which would cut the wave's first
    /// network call mid-flight.
    #[tokio::test(start_paused = true)]
    async fn a_wave_resolves_ambiguous_dispatches_instead_of_dying() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _edges) = build_graph(vec![
            request("kept", T, false, &[]),
            request("ghost", T, false, &[]),
            request("unrecorded", T, false, &[]),
        ])
        .expect("valid graph");
        let ids = |name: &str| node_task_id(request_by_name(name, &nodes)).expect("task id");
        let (kept, ghost, unrecorded) = (ids("kept"), ids("ghost"), ids("unrecorded"));
        let layer: Vec<String> = nodes.keys().cloned().collect();
        let server = MockCi::start(&["ghost"], &["unrecorded"], "1.99.0").await;
        let dispatch = local_dispatch(&server.url);
        let rustc = WireRustcVersion::parse("1.99.0").expect("rustc");
        let policy = DispatchPolicy {
            rustc_version: &rustc,
            in_flight: 8,
        };
        let mut reruns = Vec::new();
        {
            // One task per run, one slot per run — each node gets
            // its own dispatch so the scripted answers key on it.
            let drive = drive_layer(
                &dispatch,
                &layer,
                LayerPosition { index: 0, of: 1 },
                &mut nodes,
                &mut reruns,
                &policy,
                at(0),
            );
            tokio::pin!(drive);
            let (bound_tx, bound) = tokio::sync::oneshot::channel::<()>();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(60));
                let _ = bound_tx.send(());
            });
            tokio::select! {
                result = &mut drive => result.expect("every node built"),
                _ = bound => panic!("the wave did not finish inside its real bound"),
            }
        }
        assert!(nodes.values().all(|node| node.done));
        {
            let state = server.state.lock().expect("mock state");
            for id in &layer {
                assert_eq!(
                    state
                        .recorded
                        .iter()
                        .filter(|(task_id, _)| task_id == id)
                        .count(),
                    1,
                    "{id} recorded exactly once"
                );
            }
            // The unrecorded 500 re-sent exactly once; the recorded one
            // and the clean dispatch never re-sent.
            assert_eq!(
                state
                    .seen
                    .iter()
                    .filter(|task_id| **task_id == unrecorded)
                    .count(),
                2
            );
            assert_eq!(
                state
                    .seen
                    .iter()
                    .filter(|task_id| **task_id == ghost)
                    .count(),
                1
            );
            assert_eq!(
                state
                    .seen
                    .iter()
                    .filter(|task_id| **task_id == kept)
                    .count(),
                1
            );
        }
        server.shutdown().await;
    }

    /// stow#656 end to end through `Dispatch::Local`: a wave whose
    /// graph mixes covered and uncovered nodes marks the covered done
    /// through the same `mark_covered_done` the driver runs, keeps them
    /// out of every layer, and the CI server never sees a dispatch for
    /// them — each uncovered node dispatches exactly once.
    #[tokio::test(start_paused = true)]
    async fn a_wave_never_dispatches_a_covered_node() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let covered_leaf = request("served", T, false, &[]);
        let fresh = request("fresh", T, false, &[]);
        let dependent = request("dependent", T, false, &[("served", T, false)]);
        let covered_id = covered_leaf.task_id().expect("served id");
        let (mut nodes, edges) =
            build_graph(vec![covered_leaf, fresh, dependent]).expect("valid graph");
        let ids = |name: &str| node_task_id(request_by_name(name, &nodes)).expect("task id");
        let (fresh, dependent) = (ids("fresh"), ids("dependent"));
        let covered = BTreeSet::from([covered_id.clone()]);
        assert_eq!(mark_covered_done(&mut nodes, &covered), 1);
        let layers = layer_graph(&nodes, &edges, &covered).expect("layers");
        let server = MockCi::start(&[], &[], "1.99.0").await;
        let dispatch = local_dispatch(&server.url);
        let rustc = WireRustcVersion::parse("1.99.0").expect("rustc");
        let policy = DispatchPolicy {
            rustc_version: &rustc,
            in_flight: 8,
        };
        let mut reruns = Vec::new();
        {
            let drive = async {
                for (index, layer) in layers.iter().enumerate() {
                    if layer.is_empty() {
                        continue;
                    }
                    mark_blocked(layer, &mut nodes, &edges);
                    drive_layer(
                        &dispatch,
                        layer,
                        LayerPosition {
                            index,
                            of: layers.len(),
                        },
                        &mut nodes,
                        &mut reruns,
                        &policy,
                        at(0),
                    )
                    .await?;
                }
                Ok::<(), stow_types::error::Error>(())
            };
            tokio::pin!(drive);
            let (bound_tx, bound) = tokio::sync::oneshot::channel::<()>();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(60));
                let _ = bound_tx.send(());
            });
            tokio::select! {
                result = &mut drive => result.expect("every uncovered node built"),
                _ = bound => panic!("the wave did not finish inside its real bound"),
            }
        }
        assert!(nodes.values().all(|node| node.done));
        {
            let state = server.state.lock().expect("mock state");
            assert!(
                !state.seen.contains(&covered_id),
                "the covered leaf was never dispatched"
            );
            for id in [&fresh, &dependent] {
                assert_eq!(
                    state.seen.iter().filter(|task_id| *task_id == id).count(),
                    1,
                    "{id} dispatched exactly once"
                );
            }
        }
        server.shutdown().await;
    }
}
