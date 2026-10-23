//! `stow-admin traffic-cost fixture-runs` — the `build-crate.yml`
//! runs the seeded fixture's in-flight tasks are bound to, in the
//! shape the local CI's `POST /seeded-runs` records.
//!
//! The fixture binds each in-flight row's task to a run id that no
//! dispatch through the mock ever allocated, so without these runs
//! the alarm's pending completions find no run to settle and the
//! `workflow_run` webhook reads a 404 jobs page for every task the
//! callback lane completes — a loop production never runs.
//! `scripts/traffic-cost.sh` posts them to the local CI, which
//! publishes each task's records artifact under the run's tag and
//! records the run; the shape math stays in `stow_types::fixture`,
//! never in the script.

use clap::Args;
use stow_types::fixture::FixtureShape;
use stow_types::identity::WireRustcVersion;
use stow_types::local_ci::{
    LocalCiSeededConclusion, LocalCiSeededRun, LocalCiSeededRuns, LocalCiSeededStatus,
};
use stow_types::stow_error;

use crate::render::{Output, Table, emit};

/// `stow-admin traffic-cost fixture-runs`.
#[derive(Debug, Args)]
pub struct FixtureRunsArgs {
    /// Queue rows of the fixture the scheduler holds — the size the last
    /// `scheduler budget --reset` seeded.
    #[arg(long)]
    queue_rows: u32,
}

/// Every in-flight fixture task as a finished, successful run.
fn seeded_runs(shape: FixtureShape) -> stow_types::error::Result<LocalCiSeededRuns> {
    let runs = (0..FixtureShape::IN_FLIGHT_ROWS)
        .map(|k| {
            let task = shape.in_flight_run(k);
            Ok(LocalCiSeededRun {
                workflow_run_id: Some(task.run_id),
                rustc_version: WireRustcVersion::parse(task.rustc_version.to_owned())
                    .map_err(|error| stow_error!("fixture rustc: {error}"))?,
                task_id: task.task_id,
                status: LocalCiSeededStatus::Completed {
                    conclusion: LocalCiSeededConclusion::Success,
                },
            })
        })
        .collect::<stow_types::error::Result<_>>()?;
    Ok(LocalCiSeededRuns { runs })
}

/// Print the fixture's in-flight runs.
pub fn run(args: &FixtureRunsArgs, output: Output) -> stow_types::error::Result<()> {
    let runs = seeded_runs(FixtureShape {
        queue_rows: args.queue_rows,
    })?;
    emit(output, &runs, |runs| {
        let mut table = Table::new(&["run", "rustc", "task"]);
        for run in &runs.runs {
            table.push([
                run.workflow_run_id
                    .map_or_else(|| "allocated".to_owned(), |id| id.to_string()),
                run.rustc_version.as_str().to_owned(),
                run.task_id.clone(),
            ]);
        }
        table.render()
    })
}

#[cfg(test)]
mod tests {
    use stow_types::fixture::FixtureShape;

    use super::seeded_runs;

    /// One run per in-flight row, each the row's own bound task.
    #[test]
    fn every_in_flight_task_is_one_seeded_run() {
        let shape = FixtureShape::PRODUCTION;
        let runs = seeded_runs(shape).unwrap().runs;
        assert_eq!(runs.len(), FixtureShape::IN_FLIGHT_ROWS as usize);
        for (k, run) in (0..).zip(&runs) {
            let task = shape.in_flight_run(k);
            assert_eq!(run.workflow_run_id, Some(task.run_id));
            assert_eq!(
                run.status,
                stow_types::local_ci::LocalCiSeededStatus::Completed {
                    conclusion: stow_types::local_ci::LocalCiSeededConclusion::Success
                }
            );
            assert_eq!(run.task_id, task.task_id);
            assert_eq!(run.rustc_version.as_str(), task.rustc_version);
        }
    }
}
