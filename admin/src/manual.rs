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
//! `display_title` rather than re-dispatched.

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
#[derive(Debug)]
struct RunState {
    task_id: String,
    status: String,
    conclusion: Option<String>,
    url: String,
    /// The run's `created_at` — adoption pulls the `created>=` window
    /// back to cover the oldest run the wave tracks.
    created_at: Option<time::OffsetDateTime>,
}

/// Entry point — registry sessions need a Tokio reactor, so the driver
/// runs on its own current-thread runtime like `index` does.
pub fn run(args: ManualArgs, _output: Output) -> stow_types::error::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| stow_error!("install ring CryptoProvider"))?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| stow_error!("build tokio runtime: {error}"))?
        .block_on(run_inner(args))
}

async fn run_inner(args: ManualArgs) -> stow_types::error::Result<()> {
    if args.in_flight == 0 {
        return Err(stow_error!("--in-flight must be at least 1"));
    }
    if args.crates.is_none() && args.projects.is_none() {
        return Err(stow_error!("one of --crates or --projects is required"));
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

/// Read both inputs into one request list: a crates file resolves each
/// line's newest non-yanked release (or the `@`-pinned one) with the
/// crate lane; a projects file resolves each listed repository's git
/// tree with the projects lane.
async fn resolve_sources(
    args: &ManualArgs,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<Vec<EnqueueRequest>> {
    let pool = crate::resolve::ResolvePool::new(rustc_version)?;
    let mut requests = Vec::new();
    let mut failures = Vec::new();
    if let Some(path) = &args.crates {
        let entries = load_crate_list(path)?;
        // Version lookup runs sequentially (crates.io's pace gate); the
        // resolves then fan out on the pool.
        let mut jobs: Vec<(String, semver::Version)> = Vec::with_capacity(entries.len());
        for (name, pinned) in entries {
            let release = match resolve_named_release(name.as_str(), pinned).await {
                Ok(release) => release,
                Err(error) => {
                    failures.push(format!("{name}: {error}"));
                    continue;
                }
            };
            jobs.push((name.as_str().to_owned(), release));
        }
        pool.run(
            &jobs,
            |resolver, (name, version)| {
                crate::resolve::resolve_crate(resolver, name, version, targets, rustc_version, 0)
                    .map(|source| {
                        source
                            .targets
                            .into_iter()
                            .flat_map(|(_target, tasks)| tasks)
                            .collect::<Vec<EnqueueRequest>>()
                    })
            },
            |_, (name, version), result| match result {
                Ok(tasks) => requests.extend(tasks),
                Err(error) => failures.push(format!("{name}@{version}: {error}")),
            },
        );
    }
    if let Some(path) = &args.projects {
        let repos = crate::projects::load_projects_file(path)?;
        pool.run(
            &repos,
            |resolver, repo| {
                crate::projects::resolve_repository(resolver, repo, targets, rustc_version)
            },
            |_, repo, result| match result {
                Ok(tasks) => requests.extend(tasks),
                Err(error) => failures.push(format!("{repo}: {error}")),
            },
        );
    }
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
fn load_crate_list(
    path: &Path,
) -> stow_types::error::Result<Vec<(CrateName, Option<CrateVersion>)>> {
    let raw =
        std::fs::read(path).map_err(|error| stow_error!("read {}: {error}", path.display()))?;
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
/// linked+unlinked pair of its own spelling.
async fn covered_nodes(
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

/// The three handles the index-slice pulls share.
struct Index<'a> {
    session: &'a stow_oci::RegistrySession,
    base: &'a stow_oci::RegistryBase,
    trust: &'a stow_oci::verify::Trust,
}

/// Pull and verify the published `index.<target>.<rustc>` slice —
/// `None` when the tag does not exist (a fresh registry serves an empty
/// catalog, not an error).
async fn published_slice_rows(
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

/// Drive one layer to completion: adopt runs already on the tracker,
/// dispatch the rest bounded by `in_flight`, and poll until every node
/// resolves. Nodes whose runs never materialize inside the grace window
/// surface as an error — GitHub accepted the dispatch and dropped it.
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
    // The `created>=` window is the wave's adoption horizon: it floors
    // at `--adopt-since` and can only move earlier, to the oldest run
    // the wave actually tracks — an adopted run's `created_at`, or
    // this invocation's first dispatch. A tracked run never falls out
    // of the window, and runs older than the horizon were never
    // adopted, so they cannot be mistaken for the wave's.
    let mut created_since = adopt_since;
    loop {
        for state in dispatch
            .list_runs(&open, created_since, rustc_version)
            .await?
        {
            let Some(node) = nodes.get_mut(&state.task_id) else {
                continue;
            };
            if node.run_url.is_none()
                && let Some(created) = state.created_at
            {
                created_since = created_since.min(created);
            }
            node.run_url = Some(state.url);
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
            let node = nodes.get(id).expect("open node");
            if node.dispatched {
                continue;
            }
            let payload = task_payload(id, &node.request);
            dispatch.send(&payload).await?;
            let node = nodes.get_mut(id).expect("open node");
            node.dispatched = true;
            node.dispatched_at = Some(std::time::Instant::now());
            created_since = created_since.min(time::OffsetDateTime::now_utc());
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
            Ok::<_, stow_types::error::Error>(slice_serves_layer(rows.as_deref(), layer, nodes))
        }))
        .buffered(SLICE_PULL_CONCURRENCY)
        .try_collect()
        .await?;
        if served.iter().all(|served| *served) {
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            return Err(stow_error!(
                "index publish did not serve the layer within {PUBLISH_TIMEOUT_MINUTES} minutes"
            ));
        }
        tokio::time::sleep(std::time::Duration::from_secs(INDEX_POLL_SECONDS)).await;
    }
}

/// Do every done node of this layer appear in `rows` at the shapes a
/// dependent's edge requires?
fn slice_serves_layer(
    rows: Option<&[ArtifactIndexRow]>,
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
        if !node.done {
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
        &smol::fs::read(out_dir.join("slices.json"))
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
    async fn send(&self, payload: &BuildTaskPayload) -> stow_types::error::Result<()> {
        match self {
            Self::GitHub { token } => {
                let task_json = serde_json::to_string(payload)?;
                crate::github::post_empty(
                    token,
                    &format!("actions/workflows/{WORKFLOW_FILE}/dispatches"),
                    &serde_json::json!({
                        "ref": BRANCH,
                        "inputs": { "task": task_json },
                    }),
                )
                .await
            }
            Self::Local { base } => {
                let url = format!("{base}/dispatch");
                let body = serde_json::json!({
                    "event_type": "build-crate",
                    "client_payload": payload,
                });
                let mut client = zenwave::client();
                client
                    .post(&url)?
                    .header("Content-Type", "application/json")?
                    .bytes_body(serde_json::to_vec(&body)?)
                    .await?
                    .error_for_status()
                    .await?;
                Ok(())
            }
        }
    }

    /// Every run the tracker answers for `open` — task-id keyed, so
    /// GitHub's `workflow_runs` and the local server's task list
    /// collapse onto the same record. A run's `display_title` is
    /// `<rustc>-<task_id>`: a title that does not parse, or whose rustc
    /// is not this wave's, is not one this wave could have dispatched.
    /// `created_since` is the wave's adoption horizon: GitHub filters
    /// `created=>={created_since}` and the pages are walked until
    /// exhausted — a wave's runs can exceed one page of 100.
    async fn list_runs(
        &self,
        open: &BTreeSet<String>,
        created_since: time::OffsetDateTime,
        rustc_version: &WireRustcVersion,
    ) -> stow_types::error::Result<Vec<RunState>> {
        if open.is_empty() {
            return Ok(Vec::new());
        }
        match self {
            Self::GitHub { token } => {
                let created = created_since
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|error| stow_error!("format adoption horizon: {error}"))?;
                let mut rows = Vec::new();
                let mut page = 1u32;
                loop {
                    let runs: WorkflowRunsPage = crate::github::get(
                        token,
                        &format!(
                            "actions/workflows/{WORKFLOW_FILE}/runs?event=workflow_dispatch&branch={BRANCH}&per_page=100&page={page}&created=%3E%3D{created}"
                        ),
                    )
                    .await?;
                    let last_page = runs.workflow_runs.len() < 100;
                    rows.extend(runs.workflow_runs);
                    if last_page {
                        break;
                    }
                    page += 1;
                }
                Ok(rows
                    .into_iter()
                    .filter_map(|run| {
                        let (rustc, task_id) = parse_run_title(&run.display_title)?;
                        (rustc == rustc_version.as_str() && open.contains(task_id)).then(|| {
                            RunState {
                                task_id: task_id.to_owned(),
                                status: run.status,
                                conclusion: run.conclusion,
                                url: run.html_url,
                                created_at: run.created_at.as_deref().and_then(|raw| {
                                    time::OffsetDateTime::parse(
                                        raw,
                                        &time::format_description::well_known::Rfc3339,
                                    )
                                    .ok()
                                }),
                            }
                        })
                    })
                    .collect())
            }
            Self::Local { base } => {
                let url = format!("{base}/tasks");
                let mut client = zenwave::client();
                let tasks: LocalTasksResponse = client
                    .get(&url)?
                    .await?
                    .error_for_status()
                    .await?
                    .into_json()
                    .await?;
                Ok(tasks
                    .tasks
                    .into_iter()
                    .filter_map(|run| {
                        let (rustc, task_id) = parse_run_title(&run.display_title)?;
                        (rustc == rustc_version.as_str() && open.contains(task_id)).then(|| {
                            RunState {
                                task_id: task_id.to_owned(),
                                status: run.status,
                                conclusion: run.conclusion,
                                url: run.html_url,
                                created_at: None,
                            }
                        })
                    })
                    .collect())
            }
        }
    }
}

/// The GitHub runs API's page shape — the fields the driver needs.
#[derive(serde::Deserialize)]
struct WorkflowRunsPage {
    workflow_runs: Vec<WorkflowRunRow>,
}

#[derive(serde::Deserialize)]
struct WorkflowRunRow {
    display_title: String,
    status: String,
    conclusion: Option<String>,
    html_url: String,
    created_at: Option<String>,
}

/// The local CI server's `GET /tasks` shape.
#[derive(serde::Deserialize)]
struct LocalTasksResponse {
    tasks: Vec<LocalTaskRun>,
}

#[derive(serde::Deserialize)]
struct LocalTaskRun {
    display_title: String,
    status: String,
    conclusion: Option<String>,
    html_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(blocked.is_empty());
    }

    fn request_by_name<'a>(name: &str, nodes: &'a BTreeMap<String, NodeRun>) -> &'a EnqueueRequest {
        nodes
            .values()
            .find(|node| node.request.crate_name.as_str() == name)
            .map(|node| &node.request)
            .expect("node by name")
    }
}
