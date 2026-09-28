//! `stow-admin scheduler …` — the scheduler Durable Object's operations
//! surface. Migrations live here because they are operations work, not
//! request work: the deploy pipeline calls `scheduler migrate` right
//! after `skyzen deploy`, and the route it posts to is the only code
//! that may issue DDL on the queue database.

use clap::{Args, Subcommand};
use stow_types::api::SchemaMigrationReport;

use crate::Edge;
use crate::render::{self, Output};

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
}

/// Dispatch one `scheduler` subcommand against the edge connection.
pub async fn run(
    edge: &Edge,
    args: SchedulerArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    match args.command {
        SchedulerCommand::Migrate => migrate(edge, output).await,
    }
}

async fn migrate(edge: &Edge, output: Output) -> stow_types::error::Result<()> {
    let report: SchemaMigrationReport = edge
        .post_json("/api/v1/admin/scheduler/migrate", &serde_json::json!({}))
        .await?;
    render::emit(output, &report, |report| {
        format!("scheduler schema {} → {}", report.before, report.after)
    })
}
