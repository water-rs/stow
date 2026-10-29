//! `stow-admin scheduler …` — the scheduler Durable Object's operations
//! surface. The reset lives here because it is operations work, not
//! request work: an operator runs `scheduler reset --yes` to create the
//! store's schema (or destroy and recreate it after a schema change),
//! and the route it posts to is the only code that may issue DDL on
//! the queue database.

use clap::{Args, Subcommand};
use stow_types::api::{
    SchedulerBudgetReport, SchedulerBudgetRequest, SchedulerResetReport, SchedulerSeedReport,
};

use crate::Edge;
use crate::render::{self, Output};

/// The fixture seed builds the graph and the budget pass replays every
/// scheduler drive on it, each inside one Durable Object request, so
/// both legitimately outlive the 45 s default edge bound — sized ~10× over the measured pass duration
/// at the 100k fixture.
const BUDGET_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(15);

#[derive(Args)]
pub struct SchedulerArgs {
    #[command(subcommand)]
    pub command: SchedulerCommand,
}

#[derive(Subcommand)]
pub enum SchedulerCommand {
    /// Reset the scheduler store: drop every table, index and trigger
    /// and re-execute `schema.sql`. This destroys the queue and every
    /// recorded slice, so the command refuses to run without `--yes`.
    /// `operations.yml` refills both once the reset succeeds: it
    /// dispatches `index-publish.yml` with `report=true` for every
    /// published rustc and a forced `preheat-cron.yml` wave, and a
    /// failed dispatch fails the run. It is also how a store that was
    /// never initialized gets its schema.
    Reset {
        /// Confirm the destructive reset.
        #[arg(long)]
        yes: bool,
    },
    /// The workerd cost probe — drives every scheduler route and the
    /// alarm pass on a seeded fixture and reports the real
    /// `rowsRead`/`rowsWritten` the Durable Object bills. The route
    /// answers only on deploys carrying `STOW_SCHEDULER_BUDGET=1`
    /// (the mock stack); use `seed` to load the fixture first.
    Budget {
        /// Queue rows to seed before measuring; seeding wipes the
        /// store first, so a store holding an earlier fixture is fine.
        #[arg(long)]
        queue_rows: Option<u32>,
        /// Do not seed; measure the fixture the store was last seeded
        /// with (the probe reseeds it to its canonical state).
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
    /// The hourly demand feed's native leg (stow#523): resume the
    /// durable cursor's unfinished hour — frozen pages deliver without
    /// a new Analytics Engine query — or materialize the next closed
    /// hour, freeze it on the page manifest and deliver it to
    /// `delivered`. The hourly GitHub job is the intended caller.
    DemandFeed {
        /// Materialize this specific closed hour (`YYYY-MM-DDTHH`, UTC)
        /// instead of following the durable cursor — the operator's
        /// recovery path.
        #[arg(long)]
        hour: Option<String>,
    },
}

/// Dispatch one `scheduler` subcommand against the edge connection.
pub async fn run(
    edge: &Edge,
    args: SchedulerArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    match args.command {
        SchedulerCommand::Reset { yes } => reset(edge, yes, output).await,
        SchedulerCommand::Budget {
            queue_rows,
            no_seed,
            dispatch_limit,
        } => budget(edge, queue_rows, no_seed, dispatch_limit, output).await,
        SchedulerCommand::DemandFeed { hour } => {
            crate::demand_feed::run(edge, crate::demand_feed::DemandFeedArgs { hour }, output).await
        }
    }
}

async fn reset(edge: &Edge, yes: bool, output: Output) -> stow_types::error::Result<()> {
    if !yes {
        return Err(stow_types::error::Error::msg(
            "scheduler reset drops every table, index and trigger in the store \
             and recreates `schema.sql` — the queue and recorded slices are \
             destroyed, and the operations run refills them once the reset \
             succeeds; re-run with --yes",
        ));
    }
    let report: SchedulerResetReport = edge
        .post_json("/api/v1/admin/scheduler/reset", &serde_json::json!({}))
        .await?;
    render::emit(output, &report, |report| {
        format!("scheduler store reset — {} objects dropped", report.dropped)
    })
}

/// Run `call`, repeating it up to three more times after a failure: the
/// dev runtime drops the Durable Object stub connection after a long
/// request, and the same call succeeds on a fresh one.
async fn retry_dropped_stub<T, Fut: std::future::Future<Output = stow_types::error::Result<T>>>(
    what: &str,
    mut call: impl FnMut() -> Fut,
) -> stow_types::error::Result<T> {
    let mut attempts = 0u8;
    loop {
        match call().await {
            Ok(value) => return Ok(value),
            Err(error) if attempts < 3 => {
                attempts += 1;
                eprintln!("[budget] {what} call failed, retrying: {error}");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn budget(
    edge: &Edge,
    queue_rows: Option<u32>,
    no_seed: bool,
    dispatch_limit: Option<u32>,
    output: Output,
) -> stow_types::error::Result<()> {
    if !no_seed {
        // One call wipes the store and seeds the whole fixture, so a
        // transient workerd failure (a dropped dev-runtime stub
        // connection) retries the same call rather than resuming.
        let body = serde_json::json!({ "queue_rows": queue_rows });
        let seed: SchedulerSeedReport = retry_dropped_stub("seed", || {
            edge.post_json_with_timeout(
                "/api/v1/admin/scheduler/budget/seed",
                &body,
                BUDGET_PROBE_TIMEOUT,
            )
        })
        .await?;
        eprintln!(
            "[budget] seeded: nodes={} edges={} published={}",
            seed.nodes, seed.edges, seed.published
        );
    }
    // The first call after a long seed meets the same dropped stub, and
    // the probe reseeds the fixture itself, so the retry is the same call.
    let request = SchedulerBudgetRequest { dispatch_limit };
    let report: SchedulerBudgetReport = retry_dropped_stub("probe", || {
        edge.post_json_with_timeout(
            "/api/v1/admin/scheduler/budget",
            &request,
            BUDGET_PROBE_TIMEOUT,
        )
    })
    .await?;
    let over = report.over_budget;
    render::emit(output, &report, render_budget_table)?;
    if over {
        return Err(stow_types::error::Error::msg("scheduler budget exceeded"));
    }
    Ok(())
}

/// The budget table as a terminal row set — one line per drive with its
/// four measurements against budget, the `OVER` marker on a gated
/// breach, and `SLOW` on a wall-budget breach — reported, never gated
/// (stow#567).
fn render_budget_table(report: &SchedulerBudgetReport) -> String {
    let mut out = format!("scheduler budget (queue rows {}):\n", report.queue_rows);
    for row in &report.rows {
        let marker = format!(
            "{}{}",
            if row.over_budget { " OVER" } else { "" },
            if row.over_wall { " SLOW" } else { "" },
        );
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
