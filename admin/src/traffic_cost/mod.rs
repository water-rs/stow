//! `stow-admin traffic-cost` — the pieces `scripts/traffic-cost.sh`
//! runs on one mock stack to answer whether launch user traffic fits the
//! Cloudflare allowance without overloading the scheduler (stow#772):
//!
//! - `cpu` measures Worker CPU per traffic lane under the isolate's CPU
//!   profiler and gates each lane against `WORKER_CPU_BUDGETS`;
//! - `peak` drives every lane at the launch model's peak rate and fails
//!   on any overload signal or 5xx;
//! - `verdict` judges the scheduler budget reports: row budgets, growth
//!   with stored rows, and the peak serialized Durable Object wall;
//! - `project` is the monthly projection against half of each allowance
//!   — user traffic from those reports and the CPU report, plus the
//!   preheat waves and daily resubmits the Preheat cost report measures
//!   (stow#775). The release gate runs it in its own job, once all
//!   three tests' reports exist;
//! - `fixture-runs` prints the runs the fixture's in-flight batches are
//!   bound to, which the harness records in the local CI before the
//!   callback lane completes them.

use std::path::Path;

use clap::{Args, Subcommand};
use stow_types::launch_model::LaunchModel;
use stow_types::stow_error;

use crate::Edge;
use crate::render::Output;

mod cpu;
mod fixture_runs;
mod lanes;
mod peak;
mod preheat;
mod project;
#[cfg(test)]
mod test_support;
mod verdict;

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
    /// Judge the run: row budgets, growth with stored rows and the peak
    /// serialized wall.
    Verdict(verdict::VerdictArgs),
    /// Project the month — user traffic plus the preheat waves and
    /// resubmits — against half of each product's allowance.
    Project(project::ProjectArgs),
    /// Print the `build-batch.yml` runs the fixture's in-flight batches
    /// are bound to, for the local CI's `POST /seeded-runs`.
    FixtureRuns(fixture_runs::FixtureRunsArgs),
}

/// Dispatch one `traffic-cost` subcommand.
pub async fn run(args: TrafficCostArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        TrafficCostCommand::Cpu(args) => cpu::run(&Edge::connect().await?, &args, output).await,
        TrafficCostCommand::Peak(args) => peak::run(&Edge::connect().await?, &args, output).await,
        TrafficCostCommand::Verdict(args) => verdict::run(&args, output).await,
        TrafficCostCommand::Project(args) => project::run(&args, output).await,
        TrafficCostCommand::FixtureRuns(args) => fixture_runs::run(&args, output),
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

/// Read and decode one JSON input.
async fn read_json<T: serde::de::DeserializeOwned>(
    what: &str,
    path: &Path,
) -> stow_types::error::Result<T> {
    let text = tokio::fs::read_to_string(path)
        .await
        .map_err(|error| stow_error!("read {what} {}: {error}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|error| stow_error!("parse {what} {}: {error}", path.display()))
}
