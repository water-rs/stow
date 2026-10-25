//! `stow-admin preheat cost` — the `Preheat cost` lane's commands
//! (stow#773). `scripts/preheat-cost.sh` drives a preheat wave through
//! the mock stack and calls `ledger` at every boundary it measures;
//! `report` reads what the run left in the work directory, runs
//! [`stow_types::preheat_cost::analyse`] and writes
//! `preheat-cost-report.json`. `production` is the other job's half:
//! `scripts/production-wave.sh` plans the production lanes without an
//! edge and it counts their distinct nodes into `production-wave.json`.
//!
//! The work directory's layout is this module's contract with the
//! script, per phase (`wave`, then `resubmit`):
//!
//! ```text
//! <phase>/start.json                    ledger when the phase began
//! <phase>/lanes/<NN>-<lane>/before.json ledger before the lane ran
//! <phase>/lanes/<NN>-<lane>/after.json  ledger after it exited
//! <phase>/lanes/<NN>-<lane>/plan.json   the lane's `--json` envelope
//! <phase>/lanes/<NN>-<lane>/exit        the lane's exit status
//! <phase>/rounds/<NN>/before-report.json ledger before the round's first report
//! <phase>/rounds/<NN>/end.json          ledger after its last report
//! <phase>/rounds/<NN>/new-records.json  the round's `index export` delta
//! <phase>/end.json                      ledger when the phase ended
//! ```
//!
//! The production wave's size comes from a lanes directory
//! `scripts/production-wave.sh` fills with the production lanes'
//! plan-only runs (no `--yes`, nothing enqueued), laid out like a
//! phase's lanes:
//!
//! ```text
//! <NN>-<lane>/plan.json   the lane's `--json` envelope
//! <NN>-<lane>/exit        the lane's exit status
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use stow_types::api::{ArtifactRecord, SchedulerLedger};
use stow_types::identity::{TargetTriple, WireRustcVersion};
use stow_types::local_ci::LocalCiTasks;
use stow_types::preheat_cost::{
    LaneRun, LedgerSnapshot, Node, PhaseObservations, PreheatCostReport, ProductionLane,
    ProductionTask, ProductionWave, Round, WaveObservations, analyse, count_production,
};
use stow_types::public_cache::UnitSide;
use stow_types::stow_error;
use stow_types::task_graph::TaskNodeIdentity;
use stow_types::transient::Backoff;

use crate::projects::{ProjectsPlan, SubmitOutcome};
use crate::render::{self, Output, Planned, Table};

/// `stow-admin preheat cost`.
#[derive(Args)]
pub struct CostArgs {
    #[command(subcommand)]
    command: CostCommand,
}

#[derive(Subcommand)]
enum CostCommand {
    /// Read the scheduler's probe ledger (budget-probe deploys only) and
    /// write it with the time it was read.
    Ledger(LedgerArgs),
    /// Analyse a finished run's work directory and write the report;
    /// exits nonzero when any check fails.
    Report(ReportArgs),
    /// Count the distinct nodes the production preheat lanes planned and
    /// write `production-wave.json`; exits nonzero when a lane failed or
    /// planned nothing.
    Production(ProductionArgs),
}

#[derive(Args)]
struct LedgerArgs {
    /// Where to write the snapshot.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct ReportArgs {
    /// The run's work directory (layout in this module's docs).
    #[arg(long)]
    work_dir: PathBuf,
    /// The rustc the wave built for.
    #[arg(long)]
    rustc_version: String,
    /// The local CI server's base URL — its `GET /tasks` lists every run.
    #[arg(long)]
    local_ci_url: String,
    /// Logs to search for `overloaded` answers (the edge's, each
    /// lane's, the publish loop's).
    #[arg(long)]
    scan: Vec<PathBuf>,
    /// Where to write `preheat-cost-report.json`.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct ProductionArgs {
    /// The directory holding the production lanes' plan-only runs (layout
    /// in this module's docs).
    #[arg(long)]
    lanes_dir: PathBuf,
    /// Where to write `production-wave.json`.
    #[arg(long)]
    out: PathBuf,
}

/// Command entry point.
pub async fn run(args: CostArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        CostCommand::Ledger(args) => ledger(&args).await,
        CostCommand::Report(args) => report(&args, output).await,
        CostCommand::Production(args) => production(&args, output).await,
    }
}

fn unix_millis() -> stow_types::error::Result<u64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| stow_error!("system clock before the epoch: {error}"))?;
    u64::try_from(elapsed.as_millis()).map_err(|_| stow_error!("unix millis overflow u64"))
}

async fn ledger(args: &LedgerArgs) -> stow_types::error::Result<()> {
    let edge = crate::Edge::connect().await?;
    let ledger: SchedulerLedger = edge
        .get_json("/api/v1/admin/scheduler/budget/ledger")
        .await?;
    let snapshot = LedgerSnapshot {
        taken_at_ms: unix_millis()?,
        ledger,
    };
    tokio::fs::write(&args.out, serde_json::to_vec_pretty(&snapshot)?)
        .await
        .map_err(|error| stow_error!("write {}: {error}", args.out.display()))
}

async fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> stow_types::error::Result<T> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|error| stow_error!("read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| stow_error!("parse {}: {error}", path.display()))
}

/// The entries of `dir` in name order — the script numbers them.
async fn sorted_entries(dir: &Path) -> stow_types::error::Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    let mut reader = match tokio::fs::read_dir(dir).await {
        Ok(reader) => reader,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(entries),
        Err(error) => return Err(stow_error!("list {}: {error}", dir.display())),
    };
    while let Some(entry) = reader
        .next_entry()
        .await
        .map_err(|error| stow_error!("list {}: {error}", dir.display()))?
    {
        entries.push(entry.path());
    }
    entries.sort();
    Ok(entries)
}

/// One lane's envelope: what it planned and what its submit returned.
struct LanePlan {
    tasks: Vec<stow_types::api::SubmissionTree>,
    outcome: Option<SubmitOutcome>,
    submit_failures: Vec<String>,
}

async fn lane_plan(lane: &str, dir: &Path) -> stow_types::error::Result<LanePlan> {
    let status = tokio::fs::read_to_string(dir.join("exit"))
        .await
        .map_err(|error| stow_error!("read {}/exit: {error}", dir.display()))?;
    let status = status.trim();
    if status != "0" {
        return Ok(LanePlan {
            tasks: Vec::new(),
            outcome: None,
            submit_failures: vec![format!(
                "lane exited with status {status} — see {}/stderr.log",
                dir.display()
            )],
        });
    }
    let plan_path = dir.join("plan.json");
    if lane == "projects" {
        let envelope: Planned<ProjectsPlan, SubmitOutcome> = read_json(&plan_path).await?;
        Ok(LanePlan {
            submit_failures: envelope
                .plan
                .submit_failed
                .iter()
                .map(|failed| format!("{}: {}", failed.repo, failed.reason))
                .collect(),
            tasks: envelope.plan.trees,
            outcome: envelope.result,
        })
    } else if lane == "top-binaries" {
        let envelope: Planned<crate::preheat::BinariesPlan, SubmitOutcome> =
            read_json(&plan_path).await?;
        Ok(LanePlan {
            // `skipped` holds resolve/shape skips — a ranked binary that
            // ships no binary target is an expected lane outcome, not a
            // submit failure; a failed submit POST fails the lane
            // itself, which the exit status above reports.
            submit_failures: Vec::new(),
            tasks: envelope.plan.trees,
            outcome: envelope.result,
        })
    } else {
        let envelope: Planned<Vec<stow_types::api::SubmissionTree>, SubmitOutcome> =
            read_json(&plan_path).await?;
        Ok(LanePlan {
            tasks: envelope.plan,
            outcome: envelope.result,
            submit_failures: Vec::new(),
        })
    }
}

/// Every task id a round's `index export` carried records for.
fn published_task_ids(records: &[ArtifactRecord]) -> stow_types::error::Result<BTreeSet<String>> {
    records
        .iter()
        .map(|record| {
            Ok(TaskNodeIdentity {
                crate_name: record.crate_name.clone(),
                version: record.version.clone(),
                features_json: record.features_json.clone(),
                target: record.target.clone(),
                rustc_version: record.rustc_version.clone(),
                host_side: record.unit_shape.side == UnitSide::Host,
            }
            .task_id(&record.dependency_identity()?))
        })
        .collect()
}

/// The lane directories under `lanes` in run order, each with the lane
/// name its `<NN>-<lane>` directory carries.
async fn lane_dirs(lanes: &Path) -> stow_types::error::Result<Vec<(String, PathBuf)>> {
    sorted_entries(lanes)
        .await?
        .into_iter()
        .map(|lane_dir| {
            let name = lane_dir
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.split_once('-'))
                .map(|(_, lane)| lane.to_owned())
                .ok_or_else(|| {
                    stow_error!("lane directory {} is not <NN>-<lane>", lane_dir.display())
                })?;
            Ok((name, lane_dir))
        })
        .collect()
}

/// The production lanes' plan-only output. A lane that did not exit
/// cleanly would undercount the production wave, so it fails the count
/// instead of counting as an empty lane.
async fn production_lanes(lanes_dir: &Path) -> stow_types::error::Result<Vec<ProductionLane>> {
    let mut lanes = Vec::new();
    for (name, lane_dir) in lane_dirs(lanes_dir).await? {
        let plan = lane_plan(&name, &lane_dir).await?;
        if let Some(failure) = plan.submit_failures.first() {
            return Err(stow_error!("production lane {name}: {failure}"));
        }
        lanes.push(ProductionLane {
            tasks: plan
                .tasks
                .iter()
                .flat_map(|tree| &tree.nodes)
                .map(|node| {
                    Ok(ProductionTask {
                        task_id: node.task_id.clone(),
                        target: node.target.as_str().to_owned(),
                    })
                })
                .collect::<stow_types::error::Result<_>>()?,
            lane: name,
        });
    }
    Ok(lanes)
}

/// A phase's observations plus every task its lanes planned.
///
/// `seen` holds the task ids the queue already carries: a first-seen task
/// is an inserted row, and its direct dependencies are the edges the
/// submit wrote for it. The wave phase seeds it empty — the harness
/// resets the store first — and the resubmit keeps accumulating, so each
/// phase's dedup set is exactly what its submits saw.
async fn phase(
    dir: &Path,
    seen: &mut BTreeSet<String>,
) -> stow_types::error::Result<(PhaseObservations, Vec<stow_types::api::SubmissionTree>)> {
    let mut lanes = Vec::new();
    let mut tasks = Vec::new();
    for (name, lane_dir) in lane_dirs(&dir.join("lanes")).await? {
        let plan = lane_plan(&name, &lane_dir).await?;
        let mut inserted = 0_u64;
        let mut inserted_edges = 0_u64;
        if let Some(outcome) = &plan.outcome {
            // The lane's tasks reached the scheduler: a first-seen task id
            // is a row it inserted and a dedup anchor for the next lane.
            for node in plan.tasks.iter().flat_map(|tree| &tree.nodes) {
                if seen.insert(node.task_id.clone()) {
                    inserted += 1;
                    inserted_edges += node.deps.len() as u64;
                }
            }
            if u64::from(outcome.inserted) != inserted {
                return Err(stow_error!(
                    "lane {name} posted {inserted} first-seen tasks but the scheduler inserted {}",
                    outcome.inserted
                ));
            }
        }
        lanes.push(LaneRun {
            lane: name,
            submitted: plan
                .outcome
                .as_ref()
                .map_or(0, |outcome| u64::from(outcome.submitted)),
            inserted,
            inserted_edges,
            submit_failures: plan.submit_failures,
            before: read_json(&lane_dir.join("before.json")).await?,
            after: read_json(&lane_dir.join("after.json")).await?,
        });
        tasks.extend(plan.tasks);
    }
    let mut rounds = Vec::new();
    for round_dir in sorted_entries(&dir.join("rounds")).await? {
        let records: Vec<ArtifactRecord> = read_json(&round_dir.join("new-records.json")).await?;
        rounds.push(Round {
            before_report: read_json(&round_dir.join("before-report.json")).await?,
            end: read_json(&round_dir.join("end.json")).await?,
            published: published_task_ids(&records)?,
        });
    }
    Ok((
        PhaseObservations {
            start: read_json(&dir.join("start.json")).await?,
            rounds,
            lanes,
            end: read_json(&dir.join("end.json")).await?,
        },
        tasks,
    ))
}

/// Every line of `paths` that mentions an overload.
async fn overload_sightings(paths: &[PathBuf]) -> stow_types::error::Result<Vec<String>> {
    let mut sightings = Vec::new();
    for path in paths {
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|error| stow_error!("read {}: {error}", path.display()))?;
        sightings.extend(
            String::from_utf8_lossy(&bytes)
                .lines()
                .filter(|line| line.to_ascii_lowercase().contains("overload"))
                .map(|line| format!("{}: {line}", path.display())),
        );
    }
    Ok(sightings)
}

async fn report(args: &ReportArgs, output: Output) -> stow_types::error::Result<()> {
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_error!("--rustc-version: {error}"))?;
    let mut seen = BTreeSet::new();
    let (wave, wave_tasks) = phase(&args.work_dir.join("wave"), &mut seen).await?;
    let (resubmit, _) = phase(&args.work_dir.join("resubmit"), &mut seen).await?;

    let mut nodes = BTreeMap::new();
    let mut spellings = BTreeMap::new();
    for tree in &wave_tasks {
        for node in &tree.nodes {
            let dependencies: Vec<String> = node
                .deps
                .iter()
                .map(|&dep| tree.nodes[dep as usize].task_id.clone())
                .collect();
            spellings.insert(node.task_id.clone(), node.explicit_spelling);
            nodes.insert(
                node.task_id.clone(),
                Node {
                    target: node.target.as_str().to_owned(),
                    dependencies,
                },
            );
        }
    }
    let targets: Vec<TargetTriple> = wave_tasks
        .iter()
        .flat_map(|tree| tree.nodes.iter().map(|node| node.target.clone()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let covered = crate::manual::contextual_coverage(&targets, &rustc_version, &spellings).await?;
    let runs: LocalCiTasks = crate::github::get_url_json(
        &format!("{}/tasks", args.local_ci_url.trim_end_matches('/')),
        None,
        Backoff::new(),
    )
    .await?;

    let report = analyse(&WaveObservations {
        rustc_version: rustc_version.as_str().to_owned(),
        nodes,
        wave,
        resubmit,
        runs: runs.tasks,
        covered,
        overload_sightings: overload_sightings(&args.scan).await?,
    })?;
    tokio::fs::write(&args.out, serde_json::to_vec_pretty(&report)?)
        .await
        .map_err(|error| stow_error!("write {}: {error}", args.out.display()))?;
    render::emit(output, &report, render_report)?;
    let failed = report.failures().count();
    if failed > 0 {
        return Err(stow_error!(
            "{failed} preheat cost check(s) failed — see {}",
            args.out.display()
        ));
    }
    Ok(())
}

/// `preheat cost production`: count the production lanes' distinct
/// nodes, write them as `production-wave.json` and refuse a count a
/// failed or empty lane would have understated.
async fn production(args: &ProductionArgs, output: Output) -> stow_types::error::Result<()> {
    let wave = count_production(&production_lanes(&args.lanes_dir).await?);
    wave.require_planned()?;
    tokio::fs::write(&args.out, serde_json::to_vec_pretty(&wave)?)
        .await
        .map_err(|error| stow_error!("write {}: {error}", args.out.display()))?;
    render::emit(output, &wave, render_production)
}

fn render_production(wave: &ProductionWave) -> String {
    let mut lanes = Table::new(&["lane", "planned", "new nodes"]);
    for lane in &wave.lanes {
        lanes.push([
            lane.lane.clone(),
            lane.planned.to_string(),
            lane.new_nodes.to_string(),
        ]);
    }
    let mut targets = Table::new(&["target", "nodes"]);
    for (target, count) in &wave.nodes_per_target {
        targets.push([target.clone(), count.to_string()]);
    }
    format!(
        "production wave: {} distinct nodes\n\n{}\n\n{}",
        wave.nodes,
        lanes.render(),
        targets.render()
    )
}

fn render_report(report: &PreheatCostReport) -> String {
    let mut phases = Table::new(&["phase", "rows read", "rows written", "runs", "wall s"]);
    for (name, phase) in [("wave", &report.wave), ("resubmit", &report.resubmit)] {
        phases.push([
            name.to_owned(),
            phase.rows_read.to_string(),
            phase.rows_written.to_string(),
            phase.tasks.to_string(),
            (phase.wall_ms / 1000).to_string(),
        ]);
    }
    let mut layers = Table::new(&[
        "layer",
        "published",
        "runs",
        "kind",
        "events",
        "read/event",
        "written/event",
    ]);
    for layer in &report.layers {
        for kind in &layer.kinds {
            let Some((read, written)) = kind.per_event() else {
                continue;
            };
            layers.push([
                layer.layer.to_string(),
                layer.published.to_string(),
                layer.tasks.to_string(),
                format!("{:?}", kind.kind),
                kind.events.to_string(),
                format!("{read:.1}"),
                format!("{written:.1}"),
            ]);
        }
    }
    let mut checks = Table::new(&["check", "result", "detail"]);
    for check in &report.checks {
        checks.push([
            check.name.clone(),
            if check.passed { "ok" } else { "FAILED" }.to_owned(),
            check.detail.clone(),
        ]);
    }
    format!(
        "{} nodes ({}) on rustc {}\n\n{}\n\n{}\n\n{}",
        report.nodes,
        report
            .nodes_per_target
            .iter()
            .map(|(target, count)| format!("{target}: {count}"))
            .collect::<Vec<_>>()
            .join(", "),
        report.rustc_version,
        phases.render(),
        layers.render(),
        checks.render()
    )
}
