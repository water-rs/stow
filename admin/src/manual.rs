//! `stow-admin preheat manual` — the operator-driven preheat of
//! water-rs/stow#455. Cloudflare may be fully offline: the driver
//! resolves the graph in-process, layers it topologically, dispatches
//! `build-crate.yml` runs straight through the GitHub API (or the local
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
//! dispatch runs now and is dispatched again.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use clap::Args;
use futures_util::{StreamExt as _, TryStreamExt as _};
use oci_client::manifest::OciImageManifest;
use stow_types::api::{BuildDepPin, BuildTaskPayload, EnqueueDependency, EnqueueRequest, task_id};
use stow_types::identity::{CrateName, CrateVersion, TargetTriple, WireRustcVersion};
use stow_types::index::{ArtifactIndexRow, STOW_INDEX_MEDIA_TYPE, index_tag};
use stow_types::public_cache::{UnitInvocation, required_unit_shapes};
use stow_types::records::parse_run_title;
use stow_types::registry::GHCR_BASE;
use stow_types::stow_error;
use stow_types::trusted_builder::{BRANCH, INDEX_CERTIFICATE_IDENTITY, WORKFLOW_FILE};
use zenwave::{Client, ResponseExt};

use crate::render::{self, Output};

/// The build-crate runs poll cadence.
const RUN_POLL_SECONDS: u64 = 30;
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
    /// `build-crate.yml` runs in flight at once — kept under the org's
    /// 60-runner ceiling so the repo's own CI still gets runners.
    #[arg(long, default_value_t = 45)]
    in_flight: usize,
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
    /// the D1 catalog sync runs only when this names a live edge.
    /// Defaults to `STOW_EDGE_URL`.
    #[arg(long, env = "STOW_EDGE_URL")]
    edge_url: Option<String>,
    /// How far back the GitHub runs list may reach to adopt a
    /// previous invocation's dispatches — an RFC 3339 timestamp,
    /// defaulting to 24 h ago. Runs older than this are never the
    /// wave's and are not adopted.
    #[arg(long, value_parser = parse_adopt_since)]
    adopt_since: Option<time::OffsetDateTime>,
}

/// `--adopt-since`'s RFC 3339 parse.
fn parse_adopt_since(raw: &str) -> Result<time::OffsetDateTime, String> {
    time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
        .map_err(|error| format!("{raw}: {error}"))
}

/// One node's run to completion — the dispatch knows it by `task_id`
/// (`build-crate.yml`'s `run-name`); the outcome surfaces through the
/// run's `conclusion`.
struct NodeRun {
    request: EnqueueRequest,
    /// `Some(url)` once a run exists for the task — absent while the
    /// dispatch is still inside GitHub's registration grace.
    run_url: Option<String>,
    workflow_run_id: Option<u64>,
    /// The validator for this node's bound `actions/runs/{id}` read —
    /// a 304 keeps the cached row and costs nothing against the
    /// primary rate budget. Both live and die with the node.
    run_etag: Option<String>,
    /// The last state the bound run reported — a 304's stand-in.
    latest: Option<RunState>,
    dispatched: bool,
    /// This node's own dispatch time — `RUN_GRACE_MINUTES` applies per
    /// node, not per layer.
    dispatched_at: Option<std::time::Instant>,
    done: bool,
    failed: bool,
    /// The failed ancestor that blocks this node — a node whose
    /// dependency failed, or was itself blocked behind one, is skipped
    /// before its layer dispatches.
    blocked_by: Option<String>,
}

/// The two dispatch backends, selected by `--dispatch-url`: GitHub's
/// `workflow_dispatch` API with the operator's token, or the mock's local
/// CI server.
enum Dispatch {
    /// Real GitHub Actions.
    GitHub {
        /// The operator token `crate::github_token` resolved.
        token: String,
    },
    /// The mock `stow-build serve` base URL.
    Local {
        /// Base URL — `/dispatch` and `/tasks` hang off it.
        base: String,
    },
}

/// One run's state as the driver reads it — task-id keyed, so the
/// GitHub `workflow_runs` rows (`display_title`) and the local server's
/// `MockTaskRun` list fold onto the same record. Both title shapes parse
/// through `parse_run_title`: a run whose title is not `<rustc>-<task_id>`
/// is not one this wave could have dispatched.
#[derive(Debug, Clone)]
struct RunState {
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
    latest: &mut BTreeMap<String, RunState>,
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
    let dispatch = match &args.dispatch_url {
        Some(url) => Dispatch::Local {
            base: url.trim_end_matches('/').to_owned(),
        },
        None => Dispatch::GitHub {
            token: crate::github_token().await?,
        },
    };

    let requests = resolve_sources(&args, &targets, &rustc_version).await?;
    if requests.is_empty() {
        render::emit_line("no tasks resolved");
        return Ok(());
    }
    let (mut nodes, edges) = build_graph(requests);

    let base = crate::index_cmd::registry_base()?;
    let session = base.session();
    let trust = crate::index_cmd::records_trust().await?;
    let catalog = Index {
        session: &session,
        base: &base,
        trust: &trust,
    };
    let adopt_since = args.adopt_since.unwrap_or_else(|| {
        time::OffsetDateTime::now_utc() - time::Duration::hours(ADOPT_SINCE_DEFAULT_HOURS)
    });
    let covered = covered_nodes(&catalog, &targets, &rustc_version).await?;
    tracing::info!(covered = covered.len(), "published index coverage");

    let layers = layer_graph(&nodes, &edges, &covered)?;

    let mut failures: Vec<(String, String)> = Vec::new();
    let mut blocked_report: Vec<(String, String)> = Vec::new();
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
        blocked_report.extend(mark_blocked(layer, &mut nodes, &edges));
        drive_layer(
            &dispatch,
            layer,
            &mut nodes,
            args.in_flight,
            adopt_since,
            &rustc_version,
        )
        .await?;
        for id in layer {
            let node = nodes.get(id).expect("layer node");
            if node.failed {
                failures.push((
                    id.clone(),
                    node.run_url.clone().unwrap_or_else(|| "-".to_owned()),
                ));
            }
        }
        publish_and_wait(&dispatch, &args, &nodes, layer, &catalog, &rustc_version).await?;
    }

    finish_report(&nodes, &failures, &blocked_report)
}

/// The wave's outcome line plus its failure list — a node still undone
/// failed, or was skipped behind a failed ancestor, and the report
/// names both. The run exits non-zero unless every node is done.
fn finish_report(
    nodes: &BTreeMap<String, NodeRun>,
    failures: &[(String, String)],
    blocked_report: &[(String, String)],
) -> stow_types::error::Result<()> {
    let total = nodes.len();
    let done = nodes.values().filter(|node| node.done).count();
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
    let _ = writeln!(
        report,
        "manual preheat: {done}/{total} built, {} failed, {skipped} skipped",
        failures.len()
    );
    render::emit_line(&report);
    if failures.is_empty() && done == total {
        Ok(())
    } else {
        Err(stow_error!("manual preheat incomplete"))
    }
}

/// Fold the wave into the task graph: requests keyed by task id (two
/// sources can name the same identity — dedupe by id), edges to the
/// dep's own task id so the graph keyspace is the queue's.
fn build_graph(
    requests: Vec<EnqueueRequest>,
) -> (
    BTreeMap<String, NodeRun>,
    BTreeMap<String, BTreeSet<String>>,
) {
    let mut nodes: BTreeMap<String, NodeRun> = BTreeMap::new();
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for request in requests {
        let id = node_task_id(&request);
        let deps = request
            .depends_on
            .iter()
            .map(dep_task_id)
            .collect::<BTreeSet<_>>();
        edges.entry(id.clone()).or_default().extend(deps);
        nodes.entry(id).or_insert(NodeRun {
            request,
            run_url: None,
            workflow_run_id: None,
            run_etag: None,
            latest: None,
            dispatched: false,
            dispatched_at: None,
            done: false,
            failed: false,
            blocked_by: None,
        });
    }
    (nodes, edges)
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

/// Read both inputs into one request list: a crates file resolves each
/// line's newest non-yanked release (or the `@`-pinned one) with the
/// crate lane; a projects file resolves each listed repository's git
/// tree with the projects lane.
async fn resolve_sources(
    args: &ManualArgs,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<Vec<EnqueueRequest>> {
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
    let (requests, failures) = tokio::task::spawn_blocking(move || {
        let pool = crate::resolve::ResolvePool::new(&rustc_version)?;
        let mut requests = Vec::new();
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
            );
        }
        if let Some(path) = &projects {
            let repos = tokio::runtime::Handle::current()
                .block_on(crate::projects::load_projects_file(path))?;
            let trees =
                crate::source_trees::load_optional_source_trees(source_trees.as_ref(), &repos)?;
            let mut progress = SourceProgress::new(repos.len());
            pool.run(
                &repos,
                |resolver, _runtime, repo| {
                    crate::projects::resolve_repository(
                        resolver,
                        repo,
                        &targets,
                        &rustc_version,
                        trees.as_ref().and_then(|trees| trees.get(repo)),
                    )
                },
                |_, repo, result| {
                    progress.collect(repo, result, &mut requests, &mut failures);
                },
            );
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
            );
        }
        Ok::<_, stow_types::error::Error>((requests, failures))
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
    Ok(requests)
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
/// carries.
fn node_task_id(request: &EnqueueRequest) -> String {
    task_id(
        request.crate_name.as_str(),
        &request.version.to_string(),
        &request.features_json.raw(),
        request.target.as_str(),
        request.rustc_version.as_str(),
        request.host_side,
    )
}

/// The dep's own task id — a dependency edge points at the dep's
/// identity tuple, exactly as the scheduler computes it.
fn dep_task_id(dep: &EnqueueDependency) -> String {
    task_id(
        dep.crate_name.as_str(),
        &dep.version.to_string(),
        &dep.features_json.raw(),
        dep.target.as_str(),
        dep.rustc_version.as_str(),
        dep.host_side,
    )
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
        // (name, version, features) → the shape set the slice serves.
        let mut shapes: HashMap<(String, String, String), BTreeSet<_>> = HashMap::new();
        for row in rows {
            if let Some(shape) = row.unit_shape {
                shapes
                    .entry((
                        row.crate_name.as_str().to_owned(),
                        row.version.to_string(),
                        row.features_json.raw(),
                    ))
                    .or_default()
                    .insert(shape);
            }
        }
        for ((name, version, features), served) in shapes {
            let invocation = if stow_types::api::runner_family(target.as_str())
                .is_some_and(|family| family.host_triple() == target.as_str())
            {
                UnitInvocation::Native
            } else {
                UnitInvocation::Target
            };
            if required_unit_shapes(false, invocation)
                .iter()
                .all(|shape| served.contains(shape))
            {
                covered.insert(task_id(
                    &name,
                    &version,
                    &features,
                    target.as_str(),
                    rustc_version.as_str(),
                    false,
                ));
            }
            if required_unit_shapes(true, invocation)
                .iter()
                .all(|shape| served.contains(shape))
            {
                covered.insert(task_id(
                    &name,
                    &version,
                    &features,
                    &host_triple(target),
                    rustc_version.as_str(),
                    true,
                ));
            }
        }
    }
    Ok(covered)
}

/// The three handles the index-slice pulls share — `pub` so the
/// request lane pulls the same verified slices.
pub struct Index<'a> {
    pub session: &'a stow_oci::RegistrySession,
    pub base: &'a stow_oci::RegistryBase,
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
    let reference = index.base.reference(&tag)?;
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
        &format!("{GHCR_BASE}:{tag}"),
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
        dep_pins: request
            .depends_on
            .iter()
            .map(|dep| BuildDepPin {
                crate_name: dep.crate_name.clone(),
                version: dep.version.clone(),
                features_json: dep.features_json.clone(),
                host_side: dep.host_side,
            })
            .collect(),
    }
}

/// Dispatch a node and bind it to the exact run returned by the transport.
async fn dispatch_node(
    dispatch: &Dispatch,
    task_id: &str,
    node: &mut NodeRun,
) -> stow_types::error::Result<()> {
    let payload = task_payload(task_id, &node.request);
    let workflow_run_id = dispatch.send(&payload).await?;
    node.dispatched = true;
    node.workflow_run_id = Some(workflow_run_id);
    node.dispatched_at = Some(std::time::Instant::now());
    Ok(())
}

/// Fold one observed run state into its node — shared by the one-time
/// adoption fold and every bound-run poll. A stale failure drops the
/// node's binding so it dispatches afresh; anything else binds the run
/// (`dispatched`, `run_url`) and lands done/failed removals in `open`.
fn fold_run(
    state: RunState,
    nodes: &mut BTreeMap<String, NodeRun>,
    open: &mut BTreeSet<String>,
    main_head: &str,
) {
    let Some(node) = nodes.get_mut(&state.task_id) else {
        return;
    };
    if state.stale_failure(main_head) {
        // The run this node was tracking ended as a failure of older
        // code: drop its binding so the node dispatches afresh. The match
        // is the bound run id — a fresh dispatch has no `run_url` yet and
        // must still release — while a stale row for any other id never
        // binds: an unbound node's adoption-time stale simply keeps it
        // open for a new dispatch.
        if node.workflow_run_id == Some(state.workflow_run_id) {
            node.run_url = None;
            node.workflow_run_id = None;
            node.run_etag = None;
            node.latest = None;
            node.dispatched = false;
            node.dispatched_at = None;
        }
        return;
    }
    node.run_url = Some(state.url.clone());
    node.workflow_run_id = Some(state.workflow_run_id);
    // An adopted run is a dispatch, whichever invocation sent it: it
    // counts against `in_flight` and is never sent twice.
    node.dispatched = true;
    match (state.status.as_str(), state.conclusion.as_deref()) {
        ("completed", Some("success")) => {
            node.done = true;
            open.remove(&state.task_id);
        }
        ("completed", _) => {
            node.failed = true;
            open.remove(&state.task_id);
        }
        _ => {}
    }
    node.latest = Some(state);
}

/// Drive one layer to completion: adopt once — every run in the closed
/// `[adopt_since, now]` window whose title names an open node — dispatch
/// the rest bounded by `in_flight`, then poll only the run ids the wave
/// is bound to until every node resolves. Nodes whose runs never
/// materialize inside the grace window surface as an error — GitHub
/// accepted the dispatch and dropped it.
async fn drive_layer(
    dispatch: &Dispatch,
    layer: &[String],
    nodes: &mut BTreeMap<String, NodeRun>,
    in_flight: usize,
    adopt_since: time::OffsetDateTime,
    rustc_version: &WireRustcVersion,
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
    // those ids — no listing ever runs again for this layer.
    let mut head_cache: Option<HeadCache> = None;
    let main_head = dispatch.refresh_head(&mut head_cache).await?;
    {
        let mut latest = BTreeMap::<String, RunState>::new();
        for state in dispatch
            .adopt_runs(
                &open,
                adopt_since,
                time::OffsetDateTime::now_utc(),
                rustc_version,
            )
            .await?
        {
            let Some(node) = nodes.get(&state.task_id) else {
                continue;
            };
            retain_latest_run(&mut latest, state, node.workflow_run_id);
        }
        for state in latest.into_values() {
            fold_run(state, nodes, &mut open, &main_head);
        }
    }
    loop {
        // `main`'s head is read once per poll — usually a free 304 —
        // and every row's staleness is judged against it.
        let main_head = dispatch.refresh_head(&mut head_cache).await?;
        for outcome in dispatch.poll_bound(nodes, &open, rustc_version).await? {
            match outcome {
                BoundPoll::State {
                    task_id,
                    state,
                    etag,
                } => {
                    if let Some(node) = nodes.get_mut(&task_id) {
                        node.run_etag = etag;
                    }
                    fold_run(state, nodes, &mut open, &main_head);
                }
                BoundPoll::Unmodified(task_id) => {
                    // The cached row stands; refold it — a `main` head
                    // that moved this poll can still stale it.
                    let cached = nodes.get(&task_id).and_then(|node| node.latest.clone());
                    if let Some(state) = cached {
                        fold_run(state, nodes, &mut open, &main_head);
                    }
                }
                BoundPoll::Pending => {}
            }
        }
        let mut running = open
            .iter()
            .filter(|id| {
                let node = nodes.get(*id).expect("open node");
                node.dispatched && !node.done && !node.failed
            })
            .count();
        // Dispatches stay serial — mutating calls are what GitHub's
        // secondary rate limits push back on. Only reads fan out.
        for id in &open {
            if running >= in_flight {
                break;
            }
            let node = nodes.get_mut(id).expect("open node");
            if node.dispatched {
                continue;
            }
            dispatch_node(dispatch, id, node).await?;
            running += 1;
        }
        if open.is_empty() {
            return Ok(());
        }
        let overdue: Vec<String> = open
            .iter()
            .filter(|id| {
                let node = nodes.get(*id).expect("open node");
                node.dispatched
                    && node.run_url.is_none()
                    && node.dispatched_at.is_some_and(|since| {
                        since.elapsed() > std::time::Duration::from_secs(60 * RUN_GRACE_MINUTES)
                    })
            })
            .cloned()
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
    match dispatch {
        Dispatch::GitHub { token } => {
            let mut inputs = serde_json::json!({});
            if let Some(url) = args.edge_url.clone() {
                inputs["stow_edge_url"] = serde_json::Value::String(url);
            }
            inputs["rustc_version"] = serde_json::Value::String(rustc_version.to_string());
            crate::github::post_empty(
                token,
                &format!("actions/workflows/{INDEX_PUBLISH_WORKFLOW}/dispatches"),
                &serde_json::json!({ "ref": BRANCH, "inputs": inputs }),
            )
            .await?;
        }
        Dispatch::Local { .. } => {
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
            Ok::<_, stow_types::error::Error>(slice_serves_layer(
                rows.as_deref(),
                target,
                layer,
                nodes,
            ))
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

/// Does `target`'s slice (`rows`) carry every done node of this layer
/// that lives on `target`, at the shapes a dependent's edge requires?
/// A node on another target is that target's slice's business: a layer
/// spans every CI target, and no single slice holds them all.
fn slice_serves_layer(
    rows: Option<&[ArtifactIndexRow]>,
    target: &TargetTriple,
    layer: &[String],
    nodes: &BTreeMap<String, NodeRun>,
) -> bool {
    let Some(rows) = rows else { return false };
    let mut shapes: HashMap<(String, String, String), BTreeSet<_>> = HashMap::new();
    for row in rows {
        if let Some(shape) = row.unit_shape {
            shapes
                .entry((
                    row.crate_name.as_str().to_owned(),
                    row.version.to_string(),
                    row.features_json.raw(),
                ))
                .or_default()
                .insert(shape);
        }
    }
    layer.iter().all(|id| {
        let node = nodes.get(id).expect("layer node");
        if !node.done || node.request.target != *target {
            return true;
        }
        let request = &node.request;
        let Some(served) = shapes.get(&(
            request.crate_name.as_str().to_owned(),
            request.version.to_string(),
            request.features_json.raw(),
        )) else {
            return false;
        };
        let invocation = if stow_types::api::runner_family(request.target.as_str())
            .is_some_and(|family| family.host_triple() == request.target.as_str())
        {
            UnitInvocation::Native
        } else {
            UnitInvocation::Target
        };
        required_unit_shapes(request.host_side, invocation)
            .iter()
            .all(|shape| served.contains(shape))
    })
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

impl Dispatch {
    /// Send the build-crate dispatch: GitHub's `workflow_dispatch` under
    /// the operator token, or the local server's `/dispatch` POST — the
    /// same payload the scheduler emits either way.
    async fn send(&self, payload: &BuildTaskPayload) -> stow_types::error::Result<u64> {
        match self {
            Self::GitHub { token } => {
                let task_json = serde_json::to_string(payload)?;
                let response: WorkflowDispatchResponse = crate::github::post(
                    token,
                    &format!("actions/workflows/{WORKFLOW_FILE}/dispatches"),
                    &serde_json::json!({
                        "ref": BRANCH,
                        "inputs": { "task": task_json },
                        "return_run_details": true,
                    }),
                )
                .await?;
                Ok(response.workflow_run_id)
            }
            Self::Local { base } => {
                let url = format!("{base}/dispatch");
                let body = serde_json::json!({
                    "event_type": "build-crate",
                    "client_payload": payload,
                });
                let mut client = zenwave::client();
                let response: WorkflowDispatchResponse = client
                    .post(&url)?
                    .header("Content-Type", "application/json")?
                    .bytes_body(serde_json::to_vec(&body)?)
                    .await?
                    .error_for_status()
                    .await?
                    .into_json()
                    .await?;
                Ok(response.workflow_run_id)
            }
        }
    }

    /// `main`'s head — GitHub reads it conditionally (a 304 keeps the
    /// cached sha and its etag), the local server has no ref so staleness
    /// never applies there.
    async fn refresh_head(
        &self,
        cache: &mut Option<HeadCache>,
    ) -> stow_types::error::Result<String> {
        match self {
            Self::GitHub { token } => {
                let etag = cache.as_ref().and_then(|cache| cache.etag.as_deref());
                match crate::github::get_conditional::<GitRef>(
                    token,
                    &format!("git/ref/heads/{BRANCH}"),
                    etag,
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
            Self::Local { .. } => Ok(String::new()),
        }
    }

    /// The layer's one-time adoption sweep: every run in the closed
    /// `[since, until]` window whose `<rustc>-<task_id>` title names an
    /// open node — GitHub range-enumerates `created` so the whole window
    /// is read past the 1000-row cap, and the local server answers its
    /// whole task list as before.
    async fn adopt_runs(
        &self,
        open: &BTreeSet<String>,
        since: time::OffsetDateTime,
        until: time::OffsetDateTime,
        rustc_version: &WireRustcVersion,
    ) -> stow_types::error::Result<Vec<RunState>> {
        if open.is_empty() {
            return Ok(Vec::new());
        }
        match self {
            Self::GitHub { token } => {
                let rows = crate::github::runs_in_range(
                    WORKFLOW_FILE,
                    &format!("event=workflow_dispatch&branch={BRANCH}"),
                    since,
                    until,
                    |path| async move {
                        crate::github::get::<crate::github::RunsPage<WorkflowRunRow>>(token, &path)
                            .await
                    },
                )
                .await?;
                Ok(rows
                    .into_iter()
                    .filter_map(|run| {
                        let (rustc, task_id) = parse_run_title(&run.display_title)?;
                        (rustc == rustc_version.as_str() && open.contains(task_id)).then(|| {
                            RunState {
                                task_id: task_id.to_owned(),
                                workflow_run_id: run.id,
                                status: run.status,
                                conclusion: run.conclusion,
                                url: run.html_url,
                                head_sha: run.head_sha,
                            }
                        })
                    })
                    .collect())
            }
            Self::Local { base } => local_run_states(base, open, rustc_version).await,
        }
    }

    /// Poll only the runs the wave is bound to: each open node's tracked
    /// run id gets one conditional `actions/runs/{id}` read — a 304 keeps
    /// the node's cached row — at the read bound of 8. A run id GitHub
    /// has not materialized yet answers `Pending` and stays under the
    /// node grace window. The local server keeps its `/tasks` contract:
    /// it answers the open tasks' states from one list read.
    async fn poll_bound(
        &self,
        nodes: &BTreeMap<String, NodeRun>,
        open: &BTreeSet<String>,
        rustc_version: &WireRustcVersion,
    ) -> stow_types::error::Result<Vec<BoundPoll>> {
        match self {
            Self::GitHub { token } => futures_util::stream::iter(
                open.iter()
                    .filter_map(|id| {
                        let node = nodes.get(id)?;
                        node.workflow_run_id.map(|run_id| {
                            (
                                id.clone(),
                                run_id,
                                node.run_etag.clone(),
                                node.run_url.is_some() || node.latest.is_some(),
                            )
                        })
                    })
                    .map(|(task_id, run_id, etag, observed)| async move {
                        let path = format!("actions/runs/{run_id}");
                        match crate::github::get_conditional_result::<WorkflowRunRow>(
                            token,
                            &path,
                            etag.as_deref(),
                        )
                        .await
                        {
                            Ok(crate::github::Conditional::Unmodified) => {
                                Ok(BoundPoll::Unmodified(task_id))
                            }
                            Ok(crate::github::Conditional::Modified { body: row, etag }) => {
                                let state = bound_run_state(row, run_id, &task_id, rustc_version)?;
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
            Self::Local { base } => {
                // The same tracked-id binding GitHub gets: a local row
                // that is not the node's bound run id is dropped before
                // the fold, so an old same-task completion can never
                // answer a newer bound retry.
                let mut latest = BTreeMap::<String, RunState>::new();
                for state in local_run_states(base, open, rustc_version).await? {
                    let tracked = nodes
                        .get(&state.task_id)
                        .and_then(|node| node.workflow_run_id);
                    retain_latest_run(&mut latest, state, tracked);
                }
                Ok(latest
                    .into_values()
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

/// One bound run's poll answer: a fresh row to fold, `Unmodified` when
/// the node's cached row still stands (the fold re-judges it against the
/// current `main` head), `Pending` when the run id has not materialized.
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

/// `main`'s cached head for one layer — the sha and the validator that
/// turns the next read into a 304.
struct HeadCache {
    sha: String,
    etag: Option<String>,
}

/// Fold a `GET actions/runs/{id}` row into a run state: the row's own id
/// must be the bound one and its `display_title` the node's
/// `<rustc>-<task_id>` — anything else means GitHub answered for a
/// different run, which is never a state this node may take.
fn bound_run_state(
    row: WorkflowRunRow,
    run_id: u64,
    task_id: &str,
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<RunState> {
    if row.id != run_id {
        return Err(stow_error!(
            "actions/runs/{run_id} answered with run {} — binding refused",
            row.id
        ));
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
    Ok(RunState {
        task_id: task_id.to_owned(),
        workflow_run_id: row.id,
        status: row.status,
        conclusion: row.conclusion,
        url: row.html_url,
        head_sha: row.head_sha,
    })
}

/// The local CI server's `/tasks` rows folded to run states — the same
/// contract the mock always had: title-parsed, this wave's rustc, open
/// tasks only.
async fn local_run_states(
    base: &str,
    open: &BTreeSet<String>,
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<Vec<RunState>> {
    let url = format!("{base}/tasks");
    // The shared bounded idempotent read — the local server is
    // unauthenticated, so no operator token rides it.
    let tasks: LocalTasksResponse = crate::github::get_url_json(&url, None).await?;
    Ok(tasks
        .tasks
        .into_iter()
        .filter_map(|run| {
            let (rustc, task_id) = parse_run_title(&run.display_title)?;
            (rustc == rustc_version.as_str() && open.contains(task_id)).then(|| RunState {
                task_id: task_id.to_owned(),
                workflow_run_id: run.workflow_run_id,
                status: run.status,
                conclusion: run.conclusion,
                url: run.html_url,
                head_sha: String::new(),
            })
        })
        .collect())
}

/// One run row as both `workflow_runs` listings and `actions/runs/{id}`
/// serve it — the fields the driver needs.
#[derive(serde::Deserialize)]
struct WorkflowRunRow {
    id: u64,
    display_title: String,
    head_sha: String,
    status: String,
    conclusion: Option<String>,
    html_url: String,
}

impl crate::github::RunRow for WorkflowRunRow {
    fn run_id(&self) -> u64 {
        self.id
    }
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

/// The local CI server's `GET /tasks` shape.
#[derive(serde::Deserialize)]
struct LocalTasksResponse {
    tasks: Vec<LocalTaskRun>,
}

#[derive(serde::Deserialize)]
struct WorkflowDispatchResponse {
    workflow_run_id: u64,
}

#[derive(serde::Deserialize)]
struct LocalTaskRun {
    workflow_run_id: u64,
    display_title: String,
    status: String,
    conclusion: Option<String>,
    html_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// `main`'s sha in the test fixtures.
    const MAIN_HEAD: &str = "1111111111111111111111111111111111111111";

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
            task_id: "task".to_owned(),
            workflow_run_id,
            status: status.to_owned(),
            conclusion: conclusion.map(str::to_owned),
            url: format!("https://github.com/water-rs/stow/actions/runs/{workflow_run_id}"),
            head_sha: if ran_current_code {
                MAIN_HEAD.to_owned()
            } else {
                "2222222222222222222222222222222222222222".to_owned()
            },
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

    #[test]
    fn numeric_latest_run_wins_over_unordered_old_failure() {
        let mut latest = BTreeMap::new();
        retain_latest_run(
            &mut latest,
            run_state_with_id(10, "in_progress", None, true),
            None,
        );
        retain_latest_run(
            &mut latest,
            run_state_with_id(9, "completed", Some("failure"), false),
            None,
        );
        let selected = latest.remove("task").expect("latest run");
        assert_eq!(selected.workflow_run_id, 10);
        assert_eq!(selected.status, "in_progress");
    }

    #[test]
    fn numeric_latest_run_wins_over_unordered_old_success() {
        let mut latest = BTreeMap::new();
        retain_latest_run(
            &mut latest,
            run_state_with_id(9, "completed", Some("success"), true),
            None,
        );
        retain_latest_run(
            &mut latest,
            run_state_with_id(10, "in_progress", None, true),
            None,
        );
        let selected = latest.remove("task").expect("latest run");
        assert_eq!(selected.workflow_run_id, 10);
        assert_eq!(selected.status, "in_progress");
    }

    #[test]
    fn returned_run_id_rejects_old_visibility_until_new_run_appears() {
        let mut latest = BTreeMap::new();
        retain_latest_run(
            &mut latest,
            run_state_with_id(9, "completed", Some("success"), true),
            Some(10),
        );
        assert!(latest.is_empty());
    }

    /// The smallest `EnqueueRequest` `build_graph` can fold — the test
    /// graph's task ids come from it.
    fn request(
        crate_name: &str,
        target: &str,
        host_side: bool,
        deps: &[(&str, &str, bool)],
    ) -> EnqueueRequest {
        EnqueueRequest {
            crate_name: CrateName::parse(crate_name).expect("crate name"),
            version: CrateVersion(semver::Version::new(1, 0, 0)),
            features_json: stow_types::identity::FeaturesJson::canonicalize(Vec::new())
                .expect("empty features"),
            target: TargetTriple::parse(target).expect("target"),
            rustc_version: WireRustcVersion::parse("1.99.0").expect("rustc"),
            downloads: 0,
            source: stow_types::api::EnqueueSource::CacheMiss,
            depends_on: deps
                .iter()
                .map(|(name, dep_target, dep_host)| EnqueueDependency {
                    crate_name: CrateName::parse(*name).expect("dep name"),
                    version: CrateVersion(semver::Version::new(1, 0, 0)),
                    features_json: stow_types::identity::FeaturesJson::canonicalize(Vec::new())
                        .expect("dep features"),
                    target: TargetTriple::parse(*dep_target).expect("dep target"),
                    rustc_version: WireRustcVersion::parse("1.99.0").expect("dep rustc"),
                    host_side: *dep_host,
                })
                .collect(),
            preserve_lockfile: false,
            host_side,
        }
    }

    /// A failed ancestor skips its dependents — and transitively the
    /// dependents of skipped nodes — naming the failed node as the
    /// blocker. Covered, unrelated and already-done nodes stay open.
    #[test]
    fn a_failed_dependency_skips_its_dependents() {
        const T: &str = "x86_64-unknown-linux-gnu";
        // leaf <- mid <- top, plus an unrelated independent node.
        let requests = vec![
            request("leaf", T, false, &[]),
            request("mid", T, false, &[("leaf", T, false)]),
            request("top", T, false, &[("mid", T, false)]),
            request("other", T, false, &[]),
        ];
        let (mut nodes, edges) = build_graph(requests);
        let ids = |name: &str| node_task_id(request_by_name(name, &nodes));
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
            unit_shape: Some(shape),
        }
    }

    /// A layer spans every CI target, and each slice holds only its own
    /// target's nodes: a slice serves the layer once it carries the done
    /// nodes that live on it, whatever the other targets' nodes are.
    #[test]
    fn each_slice_serves_only_its_own_targets_nodes() {
        const HOST: &str = "x86_64-unknown-linux-gnu";
        const WASM: &str = "wasm32-unknown-unknown";
        let (mut nodes, _) = build_graph(vec![
            request("macro-dep", HOST, true, &[]),
            request("lib", WASM, false, &[]),
        ]);
        for node in nodes.values_mut() {
            node.done = true;
        }
        let layer: Vec<String> = nodes.keys().cloned().collect();
        let host = TargetTriple::parse(HOST).expect("host");
        let wasm = TargetTriple::parse(WASM).expect("wasm");
        let rows_for = |name: &str, invocation: UnitInvocation, host_side: bool| {
            let request = request_by_name(name, &nodes);
            required_unit_shapes(host_side, invocation)
                .into_iter()
                .map(|shape| row_for(request, shape))
                .collect::<Vec<_>>()
        };
        let host_rows = rows_for("macro-dep", UnitInvocation::Native, true);
        let wasm_rows = rows_for("lib", UnitInvocation::Target, false);

        assert!(slice_serves_layer(Some(&host_rows), &host, &layer, &nodes));
        assert!(slice_serves_layer(Some(&wasm_rows), &wasm, &layer, &nodes));
        // A slice still missing one of its own nodes does not serve.
        assert!(!slice_serves_layer(Some(&[]), &wasm, &layer, &nodes));
        assert!(!slice_serves_layer(None, &host, &layer, &nodes));
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
        }
    }

    /// A bound-run GET must answer for the exact id the node tracks —
    /// another run's row is never this node's state, so the binding is
    /// refused rather than replaced.
    #[test]
    fn a_bound_poll_never_takes_another_run_id() {
        let rustc = WireRustcVersion::parse("1.99.0").expect("rustc");
        let row = run_row(11, "1.99.0-task", "completed", Some("success"));
        assert!(bound_run_state(row, 10, "task", &rustc).is_err());
    }

    /// The bound id's title must be the node's `<rustc>-<task_id>` — a
    /// row for a different task, a different rustc, or no task title at
    /// all is a hard error, not a fold.
    #[test]
    fn a_bound_poll_validates_the_run_title() {
        let rustc = WireRustcVersion::parse("1.99.0").expect("rustc");
        assert!(
            bound_run_state(
                run_row(10, "1.99.0-task", "completed", Some("success")),
                10,
                "task",
                &rustc
            )
            .is_ok()
        );
        assert!(
            bound_run_state(
                run_row(10, "1.99.0-other", "completed", Some("success")),
                10,
                "task",
                &rustc
            )
            .is_err()
        );
        assert!(
            bound_run_state(
                run_row(10, "1.98.0-task", "completed", Some("success")),
                10,
                "task",
                &rustc
            )
            .is_err()
        );
        assert!(
            bound_run_state(
                run_row(10, "no-task-title", "completed", Some("success")),
                10,
                "task",
                &rustc
            )
            .is_err()
        );
    }

    /// Mixed fold outcomes across one poll: a completed success marks
    /// done, a completed failure on current code marks failed, an
    /// in-flight run binds and stays open, and a failure on moved `main`
    /// code unbinds for redispatch — a tracked old run id stays bound to
    /// its node instead of being dispatched again.
    #[test]
    fn a_poll_folds_each_bound_run_by_its_outcome() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) = build_graph(vec![
            request("won", T, false, &[]),
            request("lost", T, false, &[]),
            request("flying", T, false, &[]),
            request("stale", T, false, &[]),
        ]);
        let ids: BTreeMap<&str, String> = ["won", "lost", "flying", "stale"]
            .into_iter()
            .map(|name| (name, node_task_id(request_by_name(name, &nodes))))
            .collect();
        let mut open: BTreeSet<String> = nodes.keys().cloned().collect();

        let mut states = BTreeMap::<String, RunState>::new();
        for (name, run_id, status, conclusion) in [
            ("won", 100, "completed", Some("success")),
            ("lost", 101, "completed", Some("failure")),
            ("flying", 102, "in_progress", None),
        ] {
            let task = ids[name].clone();
            let mut state = run_state_with_id(run_id, status, conclusion, true);
            state.task_id = task;
            retain_latest_run(&mut states, state, None);
        }
        for state in states.into_values() {
            fold_run(state, &mut nodes, &mut open, MAIN_HEAD);
        }

        let won = ids["won"].clone();
        let lost = ids["lost"].clone();
        let flying = ids["flying"].clone();
        assert!(nodes[&won].done && !open.contains(&won));
        assert!(nodes[&lost].failed && !open.contains(&lost));
        assert!(!nodes[&flying].done && !nodes[&flying].failed && nodes[&flying].dispatched);
        assert_eq!(nodes[&flying].workflow_run_id, Some(102));
        // An adopted/dispatched run counts as bound — no re-dispatch.
        assert!(nodes[&flying].dispatched);

        // The stale node: its bound run failed on code `main` moved
        // past — the binding drops and the node can dispatch again. The
        // bound id is what releases, not a URL: a freshly dispatched
        // node has no `run_url` yet and must still free.
        let stale = ids["stale"].clone();
        let mut old_run = run_state_with_id(50, "completed", Some("failure"), false);
        old_run.task_id = stale.clone();
        let node = nodes.get_mut(&stale).expect("stale node");
        node.workflow_run_id = Some(50);
        node.dispatched = true;
        node.dispatched_at = Some(std::time::Instant::now());
        fold_run(old_run, &mut nodes, &mut open, MAIN_HEAD);
        let node = &nodes[&stale];
        assert!(
            node.workflow_run_id.is_none()
                && node.run_url.is_none()
                && !node.dispatched
                && node.dispatched_at.is_none()
                && node.run_etag.is_none()
                && node.latest.is_none()
        );
        assert!(open.contains(&stale));
    }

    /// A stale row that is not the node's bound id never releases it —
    /// and a node with no bound id ignores adoption-time stale rows
    /// instead of binding them.
    #[test]
    fn only_the_bound_run_id_releases_on_stale() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let (mut nodes, _) = build_graph(vec![request("bound", T, false, &[])]);
        let task = node_task_id(request_by_name("bound", &nodes));
        let mut open: BTreeSet<String> = nodes.keys().cloned().collect();
        nodes.get_mut(&task).expect("node").workflow_run_id = Some(50);
        nodes.get_mut(&task).expect("node").dispatched = true;

        let mut other = run_state_with_id(99, "completed", Some("failure"), false);
        other.task_id = task.clone();
        fold_run(other, &mut nodes, &mut open, MAIN_HEAD);
        assert_eq!(nodes[&task].workflow_run_id, Some(50));
        assert!(nodes[&task].dispatched);
    }

    /// The tracked-id filter every poll and adoption applies through
    /// `retain_latest_run`: an old same-task completion cannot answer a
    /// newer bound retry — it drops before the fold, while the bound id
    /// itself lands.
    #[test]
    fn an_old_same_task_completion_cannot_answer_a_bound_retry() {
        let mut latest = BTreeMap::new();
        let mut old = run_state_with_id(40, "completed", Some("success"), true);
        old.task_id = "task".to_owned();
        retain_latest_run(&mut latest, old, Some(50));
        assert!(latest.is_empty(), "untracked id dropped before the fold");

        let mut bound = run_state_with_id(50, "completed", Some("success"), true);
        bound.task_id = "task".to_owned();
        retain_latest_run(&mut latest, bound, Some(50));
        assert_eq!(latest["task"].workflow_run_id, 50);
    }

    /// A 404 on an id whose row was already observed is GitHub dropping
    /// a materialized run — an error. Only a fresh id that never
    /// materialized waits its grace as `Pending`.
    #[test]
    fn a_404_on_an_observed_run_is_missing_not_pending() {
        assert!(run_404(50, true).is_err());
        assert!(matches!(run_404(50, false), Ok(BoundPoll::Pending)));
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
                body: r#"{"tasks":[{"workflow_run_id":7,"display_title":"1.99.0-taskabc","status":"completed","conclusion":"success","html_url":"http://localhost/run/7"}]}"#,
            },
        ])
        .await;
        let rustc = WireRustcVersion::parse("1.99.0").expect("rustc version parses");
        let open = BTreeSet::from(["taskabc".to_owned()]);
        let runs = local_run_states(&server.url, &open, &rustc)
            .await
            .expect("a dropped connection retries");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].task_id, "taskabc");
        assert_eq!(runs[0].workflow_run_id, 7);
        let heads = server.join().await;
        assert_eq!(heads.len(), 2);
        for head in &heads {
            assert!(
                !head.headers.contains_key(http::header::AUTHORIZATION),
                "the local read must not send an Authorization header: {:?}",
                head.headers
            );
        }
    }
}
