//! `stow-admin request` — the human request lane's Actions leg (stow#428).
//!
//! `resolve-request.yml` runs `request resolve` with the edge's `request`
//! dispatch input: the admitted crate/version/features/rustc are resolved
//! in-process by `stow-resolver` across `CI_TARGET_TRIPLES`, coverage is
//! pruned against the published `index.<target>.<rustc>` slices — the same
//! membership the scheduler's dependency gate reads — and the outcome is
//! reported through the edge's trusted submit surface under this job's
//! OIDC identity, the credential every submit lane shares.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use stow_resolver::TaskNode;
use stow_types::api::{
    CI_TARGET_TRIPLES, CrateRequestStatus, EnqueueRequest, EnqueueSource, RequestDispatch,
    RequestOutcome, RequestOutcomeReport, RequestRootOutcome, task_id,
};
use stow_types::identity::TargetTriple;
use stow_types::stow_error;

use crate::Edge;
use crate::render::{self, Output, Table};

#[derive(Args)]
pub struct RequestArgs {
    #[command(subcommand)]
    command: RequestCommand,
}

#[derive(Subcommand)]
enum RequestCommand {
    /// Resolve one admitted human request across the CI targets and
    /// report its outcome — the Actions leg of `POST /api/v1/requests`.
    Resolve(RequestResolveArgs),
}

#[derive(Args)]
struct RequestResolveArgs {
    /// The `request` `workflow_dispatch` input — the edge's JSON-encoded
    /// [`RequestDispatch`]: request id and attempt, crate, version,
    /// features, rustc, the closure cap and the dispatch timestamp the
    /// `dispatch_to_submit_ms` measurement is taken from.
    #[arg(long)]
    request: String,
    /// `CARGO_HOME` the resolve uses — `resolve-request.yml` points it
    /// at the cache-restored directory so the sparse index stays warm
    /// between runs; omitted, a fresh tempdir resolves cold.
    #[arg(long)]
    cargo_home: Option<PathBuf>,
    /// Report the outcome to the scheduler. Without it the resolved
    /// plan is printed and nothing is sent.
    #[arg(long)]
    yes: bool,
}

/// Everything `resolve` reports: the uncovered task batch across the
/// targets plus the per-target root facts the record's outcome table is
/// assembled from.
struct RequestPlan {
    /// The `EnqueueRequest`s of every target whose lib root was not
    /// already published — sent to the trusted enqueue verbatim.
    tasks: Vec<EnqueueRequest>,
    /// Per-target root facts, in `CI_TARGET_TRIPLES` order.
    roots: Vec<RequestRootOutcome>,
    /// `(target, uncovered task count)` for the plan render.
    counts: Vec<(TargetTriple, usize)>,
    /// The largest single-target uncovered closure — what the record's
    /// `max_closure` caps.
    closure_size: usize,
}

pub async fn run(args: RequestArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        RequestCommand::Resolve(args) => resolve(args, output).await,
    }
}

async fn resolve(args: RequestResolveArgs, output: Output) -> stow_types::error::Result<()> {
    let dispatch: RequestDispatch = serde_json::from_str(&args.request)
        .map_err(|error| stow_error!("--request payload: {error}"))?;
    match plan_request(&dispatch, args.cargo_home).await {
        Ok(plan) => {
            if !args.yes {
                return render_plan(&dispatch, &plan, output);
            }
            submit_outcome(&dispatch, plan, output).await
        }
        Err(error) => {
            if args.yes {
                // A dead resolve leaves the record `resolving` forever
                // unless its failure is reported — post it; a report
                // failure only logs, the run's `completed` webhook is
                // the backstop.
                match Edge::connect().await {
                    Ok(edge) => {
                        if let Err(report_error) =
                            report_failure(&edge, &dispatch, &error.to_string()).await
                        {
                            tracing::error!(%report_error, "request outcome report failed");
                        }
                    }
                    Err(connect_error) => tracing::error!(
                        %connect_error,
                        "edge connect for the outcome report failed"
                    ),
                }
            }
            Err(error)
        }
    }
}

/// Resolve the request and assemble its outcome report. The failure is
/// returned for [`resolve`] to report — the record's `failed` state must
/// name the real step, not a webhook timeout.
async fn plan_request(
    dispatch: &RequestDispatch,
    cargo_home: Option<PathBuf>,
) -> stow_types::error::Result<RequestPlan> {
    let seed = dispatch.features_json.features().to_vec();
    let no_default_features = !seed.iter().any(|feature| feature == "default");
    let targets: Vec<TargetTriple> = CI_TARGET_TRIPLES
        .iter()
        .map(|target| {
            TargetTriple::parse((*target).to_owned())
                .expect("CI_TARGET_TRIPLES entries always parse")
        })
        .collect();
    let crate_name = dispatch.crate_name.as_str().to_owned();
    let version = dispatch.version.as_semver().clone();
    let rustc_version = dispatch.rustc_version.clone();
    // `spawn_blocking` because a resolve is mostly synchronous cargo
    // work; the blocking thread still carries the runtime context, so
    // `Handle::current()` drives the tarball fetch — the same shape
    // `preheat plan` uses.
    let outputs = tokio::task::spawn_blocking({
        let rustc_version = rustc_version.clone();
        let version = version.clone();
        let crate_name = crate_name.clone();
        let targets = crate::resolve::target_strings(&targets);
        // The closure's error type is the resolver's own — anyhow — so
        // `?` propagates `io`/`cargo` failures and the outer map_err
        // adds the request context.
        move || {
            let shim = std::env::current_exe()?;
            let resolver = match cargo_home {
                Some(home) => stow_resolver::Resolver::with_cargo_home(home, &rustc_version, shim),
                None => stow_resolver::Resolver::new(&rustc_version, shim),
            }?;
            let runtime = tokio::runtime::Handle::current();
            runtime.block_on(resolver.resolve_crate_units(
                &crate_name,
                &version,
                &stow_resolver::ResolveOptions {
                    features: seed,
                    no_default_features,
                    ..stow_resolver::ResolveOptions::default()
                },
                &targets,
            ))
        }
    })
    .await
    // A panicked resolve is still a failure the record must hear about
    // — the JoinError becomes the reported error, not a process abort.
    .map_err(|error| stow_error!("resolve task: {error}"))?
    .map_err(|error| {
        stow_error!(
            "resolve {} {}: {error:#}",
            dispatch.crate_name,
            dispatch.version
        )
    })?;

    let mut parts = Vec::with_capacity(outputs.len());
    let mut all_nodes = BTreeSet::new();
    for (target, output) in &outputs {
        let target_parts = stow_resolver::request_plan_parts(
            &output.units,
            &output.roots,
            &crate_name,
            &version,
            target,
        )
        .map_err(|error| stow_error!("plan {crate_name} {version} for {target}: {error:#}"))?;
        all_nodes.extend(target_parts.nodes.iter().cloned());
        parts.push((target.clone(), target_parts));
    }

    // Coverage is the published index's own membership — the same set
    // the queue's dependency gate serves — so a `cached` root or a
    // pruned dep is one the serving path can actually hand out.
    let base = crate::index_cmd::registry_base()?;
    let session = base.session();
    let trust = crate::index_cmd::records_trust().await?;
    let catalog = crate::manual::Index {
        session: &session,
        base: &base,
        trust: &trust,
    };
    let covered_ids = crate::manual::covered_nodes(&catalog, &targets, &rustc_version).await?;
    let covered: BTreeSet<TaskNode> = all_nodes
        .into_iter()
        .filter(|node| covered_ids.contains(&node_task_id(node, &rustc_version)))
        .collect();

    assemble_plan(parts, &covered, &rustc_version, dispatch.max_closure)
}

/// Plan parts + the covered set → the outcome report's tasks and roots.
/// Split from [`plan_request`] so the assembly is host-testable.
///
/// A covered lib root reports `cached` and its target's closure is not
/// enqueued — matching the lane the Worker used to run. The largest
/// single-target uncovered closure is what `max_closure` caps.
fn assemble_plan(
    parts: Vec<(String, stow_resolver::RequestPlanParts)>,
    covered: &BTreeSet<TaskNode>,
    rustc_version: &stow_types::identity::WireRustcVersion,
    max_closure: u32,
) -> stow_types::error::Result<RequestPlan> {
    let mut tasks = Vec::new();
    let mut roots = Vec::with_capacity(parts.len());
    let mut counts = Vec::with_capacity(parts.len());
    let mut closure_size = 0_usize;
    for (target, target_parts) in parts {
        let target = TargetTriple::parse(&target)
            .map_err(|error| stow_error!("plan target `{target}`: {error}"))?;
        let root_cached = target_parts
            .root_key
            .as_ref()
            .is_some_and(|key| covered.contains(key));
        roots.push(RequestRootOutcome {
            target: target.clone(),
            task_id: target_parts
                .root_key
                .as_ref()
                .map(|key| node_task_id(key, rustc_version)),
            cached: root_cached,
        });
        if root_cached {
            counts.push((target, 0));
            continue;
        }
        let (requests, uncovered) = stow_resolver::enqueue_requests_inner(
            &target_parts.nodes,
            &target_parts.edges,
            covered,
            rustc_version,
            EnqueueSource::HumanRequest,
            0,
        );
        counts.push((target, uncovered.len()));
        closure_size = closure_size.max(uncovered.len());
        tasks.extend(requests);
    }
    if u64::try_from(closure_size).unwrap_or(u64::MAX) > u64::from(max_closure) {
        return Err(stow_error!(
            "dependency graph exceeds size limit ({closure_size} uncovered tasks \
             > max_closure {max_closure})"
        ));
    }
    Ok(RequestPlan {
        tasks,
        roots,
        counts,
        closure_size,
    })
}

/// The scheduler task id `node` mints — the id `enqueue` deduplicates
/// on and the record's root lookups key on.
fn node_task_id(node: &TaskNode, rustc_version: &stow_types::identity::WireRustcVersion) -> String {
    task_id(
        node.crate_name.as_str(),
        &node.version.to_string(),
        &node.features_json,
        &node.target,
        rustc_version.as_str(),
        node.host_side,
    )
}

/// `POST /api/v1/scheduler/requests/{request_id}/outcome` — the report
/// the record waits on. The tasks ride the same trusted submit surface
/// the preheat lanes use; the edge route enqueues them and writes the
/// record's `enqueued` outcome in one call.
async fn post_outcome(
    edge: &Edge,
    dispatch: &RequestDispatch,
    report: &RequestOutcomeReport,
) -> stow_types::error::Result<CrateRequestStatus> {
    edge.post_json(
        &format!("/api/v1/scheduler/requests/{}/outcome", dispatch.request_id),
        report,
    )
    .await
}

/// The resolve's failure report — the same route, tasks empty and
/// `error` set, so the record reads the real reason.
async fn report_failure(
    edge: &Edge,
    dispatch: &RequestDispatch,
    error: &str,
) -> stow_types::error::Result<()> {
    let report = RequestOutcomeReport {
        attempt: dispatch.attempt,
        outcome: RequestOutcome::Failed {
            error: error.to_owned(),
        },
    };
    let _: CrateRequestStatus = post_outcome(edge, dispatch, &report).await?;
    Ok(())
}

/// Post the plan's outcome and print the per-target table the request
/// page later renders from the record.
async fn submit_outcome(
    dispatch: &RequestDispatch,
    plan: RequestPlan,
    output: Output,
) -> stow_types::error::Result<()> {
    let edge = Edge::connect().await?;
    let report = RequestOutcomeReport {
        attempt: dispatch.attempt,
        outcome: RequestOutcome::Resolved {
            tasks: plan.tasks,
            roots: plan.roots,
        },
    };
    let status: CrateRequestStatus = post_outcome(&edge, dispatch, &report).await?;
    // The measurement the issue asks for: dispatch to the submit's
    // landing, one line, `dispatched_at` stamped by the edge.
    let elapsed_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
        .saturating_sub(u64::try_from(dispatch.dispatched_at).unwrap_or(0));
    tracing::info!(
        dispatch_to_submit_ms = elapsed_secs.saturating_mul(1000),
        request_id = %dispatch.request_id,
        "request resolve submitted"
    );
    render::emit(output, &status, |status| {
        let mut out = format!(
            "{} {} (rustc {}) — {}\n",
            status.crate_name, status.version, status.rustc_version, dispatch.request_id
        );
        if let Some(error) = &status.error {
            let _ = writeln!(out, "failed: {error}");
        }
        let mut table = Table::new(&["target", "state", "task"]);
        for target in &status.targets {
            table.push([
                target.target.as_str().to_owned(),
                serde_json::to_value(target.state)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default(),
                target.task_id.clone().unwrap_or_default(),
            ]);
        }
        let _ = write!(out, "{}", table.render());
        out.trim_end().to_owned()
    })
}

/// The dry-run render: what the resolve computed and what `--yes` would
/// submit.
fn render_plan(
    dispatch: &RequestDispatch,
    plan: &RequestPlan,
    output: Output,
) -> stow_types::error::Result<()> {
    render::emit(
        output,
        &serde_json::json!({
            "request_id": dispatch.request_id,
            "crate_name": dispatch.crate_name,
            "version": dispatch.version,
            "rustc_version": dispatch.rustc_version,
            "tasks": plan.tasks.len(),
            "closure_size": plan.closure_size,
        }),
        |payload| {
            let mut out = format!(
                "{} {} (rustc {}) — {}\n",
                dispatch.crate_name,
                dispatch.version,
                dispatch.rustc_version,
                payload["request_id"].as_str().unwrap_or_default(),
            );
            let mut table = Table::new(&["target", "uncovered tasks"]);
            for (target, count) in &plan.counts {
                table.push([target.as_str().to_owned(), count.to_string()]);
            }
            let _ = write!(out, "{}", table.render());
            let _ = write!(
                out,
                "\n{} task(s) to submit{}",
                plan.tasks.len(),
                if plan.tasks.is_empty() {
                    ""
                } else {
                    " — pass --yes"
                }
            );
            out
        },
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use stow_resolver::{RequestPlanParts, TaskNode};
    use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, WireRustcVersion};

    use super::*;

    fn dispatch() -> RequestDispatch {
        RequestDispatch {
            request_id: "req-serde-1.0.219-abc-1.99.0".to_owned(),
            attempt: 1,
            run_title: "resolve-a1-req-serde-1.0.219-abc-1.99.0".to_owned(),
            crate_name: CrateName::parse("serde").expect("name"),
            version: CrateVersion::new(semver::Version::new(1, 0, 219)),
            features_json: FeaturesJson::canonicalize(vec!["default".to_owned()])
                .expect("features"),
            rustc_version: WireRustcVersion::parse("1.99.0").expect("rustc"),
            max_closure: 150,
            dispatched_at: 1_700_000_000,
        }
    }

    fn node(crate_name: &str, version: &str, target: &str, host_side: bool) -> TaskNode {
        TaskNode {
            crate_name: CrateName::parse(crate_name).expect("name"),
            version: CrateVersion::new(semver::Version::parse(version).expect("version")),
            features_json: "[\"default\"]".to_owned(),
            target: target.to_owned(),
            host_side,
        }
    }

    fn parts(
        target: &str,
        nodes: BTreeSet<TaskNode>,
        root_key: Option<TaskNode>,
    ) -> RequestPlanParts {
        RequestPlanParts {
            nodes,
            edges: BTreeMap::new(),
            root_key,
            root_target: target.to_owned(),
            root_host_side: false,
        }
    }

    /// The dispatch payload `resolve-request.yml` hands the job decodes
    /// into the typed shape the edge serialized.
    #[test]
    fn request_dispatch_round_trips() {
        let dispatch = dispatch();
        let json = serde_json::to_string(&dispatch).expect("serialize");
        let decoded: RequestDispatch = serde_json::from_str(&json).expect("decode");
        assert_eq!(decoded.request_id, dispatch.request_id);
        assert_eq!(decoded.attempt, 1);
        assert_eq!(decoded.max_closure, 150);
    }

    /// `node_task_id` mints the id the scheduler's queue assigns — the
    /// roots the job reports key on exactly it.
    #[test]
    fn node_task_id_matches_api_minting() {
        let node = node("serde", "1.0.219", "x86_64-unknown-linux-gnu", false);
        let id = node_task_id(&node, &WireRustcVersion::parse("1.99.0").expect("rustc"));
        assert_eq!(
            id,
            task_id(
                "serde",
                "1.0.219",
                "[\"default\"]",
                "x86_64-unknown-linux-gnu",
                "1.99.0",
                false
            )
        );
    }

    /// A covered lib root reports `cached` and its whole closure is
    /// skipped — the request lane does not rebuild what the published
    /// index already serves.
    #[test]
    fn covered_root_reports_cached_and_enqueues_nothing() {
        let rustc = WireRustcVersion::parse("1.99.0").expect("rustc");
        let root = node("serde", "1.0.219", "x86_64-unknown-linux-gnu", false);
        let covered: BTreeSet<TaskNode> = BTreeSet::from([root.clone()]);
        let plan = assemble_plan(
            vec![(
                "x86_64-unknown-linux-gnu".to_owned(),
                parts(
                    "x86_64-unknown-linux-gnu",
                    BTreeSet::from([root]),
                    Some(node("serde", "1.0.219", "x86_64-unknown-linux-gnu", false)),
                ),
            )],
            &covered,
            &rustc,
            150,
        )
        .expect("plan");
        assert_eq!(plan.tasks, []);
        assert_eq!(
            plan.counts,
            vec![(
                TargetTriple::parse("x86_64-unknown-linux-gnu").expect("target"),
                0
            )]
        );
        assert!(plan.roots[0].cached);
        assert!(plan.roots[0].task_id.is_some());
    }

    /// An uncovered root yields its closure's tasks minus the covered
    /// nodes — here the dep is published so only the root builds.
    #[test]
    fn uncovered_root_enqueues_the_uncovered_closure() {
        let rustc = WireRustcVersion::parse("1.99.0").expect("rustc");
        let root = node("serde", "1.0.219", "x86_64-unknown-linux-gnu", false);
        let dep = node("serde_core", "1.0.219", "x86_64-unknown-linux-gnu", false);
        let mut edges = BTreeMap::new();
        edges.insert(root.clone(), BTreeSet::from([dep.clone()]));
        let mut parts_value = parts(
            "x86_64-unknown-linux-gnu",
            BTreeSet::from([root.clone(), dep.clone()]),
            Some(root),
        );
        parts_value.edges = edges;
        // The dep is published; only the root's own task remains.
        let covered: BTreeSet<TaskNode> = BTreeSet::from([dep]);
        let plan = assemble_plan(
            vec![("x86_64-unknown-linux-gnu".to_owned(), parts_value)],
            &covered,
            &rustc,
            150,
        )
        .expect("plan");
        assert_eq!(plan.tasks.len(), 1);
        assert_eq!(plan.tasks[0].crate_name.as_str(), "serde");
        assert_eq!(plan.tasks[0].depends_on.len(), 1);
        assert_eq!(
            plan.tasks[0].depends_on[0].crate_name.as_str(),
            "serde_core"
        );
        assert_eq!(plan.closure_size, 1);
        assert!(!plan.roots[0].cached);
    }

    /// A crate with no lib target reports no root task id — the target's
    /// outcome reads `closure_queued` — and its deps still enqueue.
    #[test]
    fn no_lib_root_reports_no_task_id_but_enqueues() {
        let rustc = WireRustcVersion::parse("1.99.0").expect("rustc");
        let dep = node("serde", "1.0.219", "x86_64-unknown-linux-gnu", false);
        let plan = assemble_plan(
            vec![(
                "x86_64-unknown-linux-gnu".to_owned(),
                parts("x86_64-unknown-linux-gnu", BTreeSet::from([dep]), None),
            )],
            &BTreeSet::new(),
            &rustc,
            150,
        )
        .expect("plan");
        assert!(plan.roots[0].task_id.is_none());
        assert_eq!(plan.tasks.len(), 1);
    }

    /// The closure cap refuses the plan — the record then reads `failed`
    /// with this reason rather than a hung queue.
    #[test]
    fn closure_over_cap_fails() {
        let rustc = WireRustcVersion::parse("1.99.0").expect("rustc");
        let root = node("serde", "1.0.219", "x86_64-unknown-linux-gnu", false);
        let dep = node("serde_core", "1.0.219", "x86_64-unknown-linux-gnu", false);
        let error = assemble_plan(
            vec![(
                "x86_64-unknown-linux-gnu".to_owned(),
                parts(
                    "x86_64-unknown-linux-gnu",
                    BTreeSet::from([root, dep]),
                    Some(node("serde", "1.0.219", "x86_64-unknown-linux-gnu", false)),
                ),
            )],
            &BTreeSet::new(),
            &rustc,
            1,
        )
        .err()
        .expect("over the cap");
        assert!(error.to_string().contains("exceeds size limit"));
    }
}
