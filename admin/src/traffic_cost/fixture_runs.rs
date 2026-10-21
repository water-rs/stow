//! `stow-admin traffic-cost fixture-runs` — the `build-batch.yml` runs
//! the seeded fixture's in-flight batches are bound to, in the shape the
//! local CI's `POST /seeded-runs` records.
//!
//! The fixture binds each in-flight row's one-leg batch to a run id
//! that no dispatch through the mock ever allocated, so without these
//! runs the alarm's leg resolution reads a 404 jobs page for every
//! batch the callback lane completes and defers it until its ceiling —
//! a loop production never runs. `scripts/traffic-cost.sh` records the
//! runs and pushes each leg's records artifact under the run's tag; the
//! shape math stays in `stow_types::fixture`, never in the script.

use clap::Args;
use stow_types::fixture::FixtureShape;
use stow_types::identity::WireRustcVersion;
use stow_types::local_ci::{LocalCiSeededRun, LocalCiSeededRuns};
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

/// Every in-flight fixture batch as a finished, successful run.
fn seeded_runs(shape: FixtureShape) -> stow_types::error::Result<LocalCiSeededRuns> {
    let runs = (0..FixtureShape::IN_FLIGHT_ROWS)
        .map(|k| {
            let batch = shape.in_flight_batch(k);
            Ok(LocalCiSeededRun {
                workflow_run_id: batch.run_id,
                rustc_version: WireRustcVersion::parse(batch.rustc_version.to_owned())
                    .map_err(|error| stow_error!("fixture rustc: {error}"))?,
                batch_id: batch.batch_id,
                legs: vec![batch.task_id],
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
        let mut table = Table::new(&["run", "rustc", "batch", "leg 0"]);
        for run in &runs.runs {
            table.push([
                run.workflow_run_id.to_string(),
                run.rustc_version.as_str().to_owned(),
                run.batch_id.to_string(),
                run.legs.join(" "),
            ]);
        }
        table.render()
    })
}

#[cfg(test)]
mod tests {
    use stow_types::fixture::FixtureShape;

    use super::seeded_runs;

    /// One run per in-flight row, each the row's own bound batch with
    /// the row as its single leg.
    #[test]
    fn every_in_flight_batch_is_one_seeded_run() {
        let shape = FixtureShape::PRODUCTION;
        let runs = seeded_runs(shape).unwrap().runs;
        assert_eq!(runs.len(), FixtureShape::IN_FLIGHT_ROWS as usize);
        for (k, run) in (0..).zip(&runs) {
            let batch = shape.in_flight_batch(k);
            assert_eq!(run.workflow_run_id, batch.run_id);
            assert_eq!(run.batch_id, batch.batch_id);
            assert_eq!(run.rustc_version.as_str(), batch.rustc_version);
            assert_eq!(run.legs, [batch.task_id]);
        }
    }
}
