//! `stow-admin scheduler …` — the scheduler Durable Object's operations
//! surface. Migrations live here because they are operations work, not
//! request work: the deploy pipeline calls `scheduler migrate` right
//! after `skyzen deploy`, and the route it posts to is the only code
//! that may issue DDL on the queue database.

use clap::{Args, Subcommand};
use stow_types::api::{
    ReconcileReport, SchedulerBudgetReport, SchedulerBudgetRequest, SchedulerSeedReport,
    SchemaMigrationReport,
};

use crate::Edge;
use crate::render::{self, Output};

/// The budget pass replays every scheduler drive on the seeded fixture
/// inside one Durable Object request, so it legitimately outlives the
/// 45 s default edge bound — sized ~10× over the measured pass duration
/// at the 100k fixture.
const BUDGET_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(15);

#[derive(Args)]
pub struct SchedulerArgs {
    #[command(subcommand)]
    pub command: SchedulerCommand,
}

#[derive(Subcommand)]
pub enum SchedulerCommand {
    /// Run the pending queue schema migration and print the stored
    /// version before and after. Equal numbers mean the queue was
    /// already current.
    Migrate,
    /// The workerd cost probe — drives every scheduler route and the
    /// alarm pass on a seeded fixture and reports the real
    /// `rowsRead`/`rowsWritten` the Durable Object bills. The route
    /// answers only on deploys carrying `STOW_SCHEDULER_BUDGET=1`
    /// (the mock stack); use `seed` to load the fixture first.
    Budget {
        /// Queue rows to seed before measuring (skips seeding when the
        /// queue is already populated).
        #[arg(long)]
        queue_rows: Option<u32>,
        /// Wipe the fixture tables and reseed — needed when the local
        /// Durable Object store already holds an earlier fixture.
        #[arg(long)]
        reset: bool,
        /// Do not seed; measure against the queue as it stands.
        #[arg(long)]
        no_seed: bool,
        /// Override the deploy's dispatch cap for the alarm-pass drives.
        /// The mock deploys a tiny cap (`STOW_MAX_CONCURRENT_JOBS=3`)
        /// for its own stability — a pass run under it claims nothing
        /// and prices a claim at zero, so the harness passes the
        /// production cap from `edge/Skyzen.toml` here.
        #[arg(long)]
        dispatch_limit: Option<u32>,
    },
    /// Reconcile the scheduler's in-flight set against GitHub Actions
    /// (stow#526): classify every in-flight row (running /
    /// completed-but-unreported / missing), apply the webhook's own
    /// completion transition to the unreported and the stale-reclaim to
    /// the stale missing, and print the drift report. The watchdog
    /// runs the same pass every 15 minutes as its
    /// `edge.reconcile_drift` reading.
    Reconcile,
}

/// Dispatch one `scheduler` subcommand against the edge connection.
pub async fn run(
    edge: &Edge,
    args: SchedulerArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    match args.command {
        SchedulerCommand::Migrate => migrate(edge, output).await,
        SchedulerCommand::Budget {
            queue_rows,
            reset,
            no_seed,
            dispatch_limit,
        } => budget(edge, queue_rows, reset, no_seed, dispatch_limit, output).await,
        SchedulerCommand::Reconcile => reconcile(edge, output).await,
    }
}

async fn reconcile(edge: &Edge, output: Output) -> stow_types::error::Result<()> {
    let report: ReconcileReport = edge
        .post_json("/api/v1/admin/scheduler/reconcile", &serde_json::json!({}))
        .await?;
    render::emit(output, &report, render_reconcile_report)
}

async fn migrate(edge: &Edge, output: Output) -> stow_types::error::Result<()> {
    let report: SchemaMigrationReport = edge
        .post_json("/api/v1/admin/scheduler/migrate", &serde_json::json!({}))
        .await?;
    render::emit(output, &report, |report| {
        format!("scheduler schema {} → {}", report.before, report.after)
    })
}

async fn budget(
    edge: &Edge,
    queue_rows: Option<u32>,
    reset: bool,
    no_seed: bool,
    dispatch_limit: Option<u32>,
    output: Output,
) -> stow_types::error::Result<()> {
    if !no_seed {
        // One call seeds at most one bounded chunk — a whole 100k-row
        // fixture outlives a single DO request — so the loop ends when
        // the probe reports the seed done, not on the first response.
        // `reset` is only sent on the first call; sending it again
        // would restart the wipe it begins.
        let mut first = true;
        let mut attempts = 0u8;
        for _ in 0..1024 {
            // The seed is resumable from its `settings` cursor, so a
            // transient workerd failure (a dropped dev-runtime stub
            // connection) retries the same step rather than restarting.
            let seed: SchedulerSeedReport = match edge
                .post_json(
                    "/api/v1/admin/scheduler/budget/seed",
                    &serde_json::json!({
                        "queue_rows": queue_rows,
                        "reset": first && reset,
                    }),
                )
                .await
            {
                Ok(report) => report,
                Err(error) if attempts < 3 => {
                    attempts += 1;
                    eprintln!("[budget] seed call failed, retrying: {error}");
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            attempts = 0;
            eprintln!(
                "[budget] seed: queue={} deps={} slices={} done={}",
                seed.queue_rows, seed.dependency_rows, seed.slice_rows, seed.done
            );
            first = false;
            if seed.done {
                break;
            }
        }
    }
    let report: SchedulerBudgetReport = edge
        .post_json_with_timeout(
            "/api/v1/admin/scheduler/budget",
            &SchedulerBudgetRequest { dispatch_limit },
            BUDGET_PROBE_TIMEOUT,
        )
        .await?;
    let over = report.over_budget;
    render::emit(output, &report, render_budget_table)?;
    if over {
        return Err(stow_types::error::Error::msg("scheduler budget exceeded"));
    }
    Ok(())
}

/// The reconcile report as terminal lines — the counts, then each
/// drift row with what the pass did about it.
fn render_reconcile_report(report: &ReconcileReport) -> String {
    let mut out = format!(
        "reconcile: {} in flight ({} running, {} completed-unreported, {} missing), \
         {} runs listed — {} completions applied, {} reclaimed{}",
        report.in_flight,
        report.running,
        report.completed_unreported,
        report.missing,
        report.runs_listed,
        report.completions_applied,
        report.reclaimed,
        if report.drift { " — DRIFT" } else { "" },
    );
    for row in &report.rows {
        let _ = std::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "\n  {} {}@{} {} — {} → {}{}",
                &row.task_id[..row.task_id.len().min(12)],
                row.crate_name.as_str(),
                row.version,
                row.target.as_str(),
                row.classification.as_str(),
                row.applied.as_str(),
                row.detail
                    .as_ref()
                    .map(|detail| format!(" ({detail})"))
                    .unwrap_or_default(),
            ),
        );
    }
    out
}

/// The budget table as a terminal row set — one line per drive with its
/// four measurements against budget, and the over-budget marker.
fn render_budget_table(report: &SchedulerBudgetReport) -> String {
    let mut out = format!(
        "scheduler budget (queue rows {}, schema v{}):\n",
        report.queue_rows, report.schema_version
    );
    for row in &report.rows {
        let marker = if row.over_budget { " OVER" } else { "" };
        let _ = std::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "  {:<34} stmts={:<3}/{:<3} rows_read={:<7}/{:<7} rows_written={:<6}/{:<6} wall_ms={:<5}/{:<5}{}\n",
                row.name,
                row.statements,
                row.statement_budget,
                row.rows_read,
                row.read_budget,
                row.rows_written,
                row.write_budget,
                row.wall_ms,
                row.wall_budget,
                marker,
            ),
        );
    }
    out
}
