//! `stow-admin traffic-cost` — the pieces `scripts/traffic-cost.sh`
//! runs on one mock stack to answer whether launch user traffic fits the
//! Cloudflare allowance without overloading the scheduler (stow#772):
//!
//! - `cpu` measures Worker CPU per traffic lane under the isolate's CPU
//!   profiler and gates each lane against `WORKER_CPU_BUDGETS`;
//! - `peak` drives every lane at the launch model's peak rate and fails
//!   on any overload signal or 5xx;
//! - `project` judges the scheduler budget reports and the CPU report:
//!   row budgets, growth with stored rows, the monthly projection against
//!   half of each allowance, and the peak serialized Durable Object wall.

use std::path::Path;

use clap::{Args, Subcommand};
use stow_types::launch_model::LaunchModel;
use stow_types::stow_error;

use crate::Edge;
use crate::render::Output;

mod cpu;
mod lanes;
mod peak;
mod project;

/// `stow-admin traffic-cost`.
#[derive(Debug, Args)]
pub struct TrafficCostArgs {
    #[command(subcommand)]
    command: TrafficCostCommand,
}

#[derive(Debug, Subcommand)]
enum TrafficCostCommand {
    /// Measure Worker CPU per traffic lane through the edge's `DevTools`
    /// inspector and fail on a lane over its budget.
    Cpu(cpu::CpuArgs),
    /// Drive every traffic lane at the launch model's peak rate and fail
    /// on any overload signal, 5xx, error share or latency bound.
    Peak(peak::PeakArgs),
    /// Judge the run: row budgets, growth with stored rows, the monthly
    /// projection against the allowance, and the peak serialized wall.
    Project(project::ProjectArgs),
}

/// Dispatch one `traffic-cost` subcommand.
pub async fn run(args: TrafficCostArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        TrafficCostCommand::Cpu(args) => cpu::run(&Edge::connect().await?, &args, output).await,
        TrafficCostCommand::Peak(args) => peak::run(&Edge::connect().await?, &args, output).await,
        TrafficCostCommand::Project(args) => project::run(&args, output).await,
    }
}

/// Read the checked-in launch model.
async fn read_model(path: &Path) -> stow_types::error::Result<LaunchModel> {
    let text = tokio::fs::read_to_string(path)
        .await
        .map_err(|error| stow_error!("read launch model {}: {error}", path.display()))?;
    LaunchModel::from_toml(&text)
        .map_err(|error| stow_error!("load launch model {}: {error}", path.display()))
}
