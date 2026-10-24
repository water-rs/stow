//! Fixtures the `verdict`, `project` and `preheat` unit tests share.

use stow_types::api::{SchedulerBudgetReport, SchedulerBudgetRow};
use stow_types::do_budgets::{DO_BUDGETS, WORKER_CPU_BUDGETS};
use stow_types::launch_model::LaunchModel;

use super::cpu::{WorkerCpuReport, WorkerCpuRow};

/// A fixture report built on the absolute budget bounds: every
/// drive's measurement sits at `scale(name)` of its budget — half is
/// the ~2× headroom the `DO_BUDGETS` table documents, so the fixture
/// is the report a healthy run produces.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "fixture counters sit far inside both types' ranges"
)]
pub(super) fn fixture_report(
    queue_rows: u64,
    scale: impl Fn(&str) -> f64,
) -> SchedulerBudgetReport {
    SchedulerBudgetReport {
        queue_rows,
        // The production dispatch cap (45) minus the fixture's 30
        // in-flight rows: the slots the hot pass claims.
        dispatch_limit: 45,
        claimed_tasks: 15,
        over_budget: false,
        rows: DO_BUDGETS
            .iter()
            .map(|budget| {
                let factor = scale(budget.name);
                SchedulerBudgetRow {
                    name: budget.name.to_owned(),
                    statements: (budget.statements as f64 * factor) as u64,
                    rows_read: (budget.rows_read as f64 * factor) as u64,
                    rows_written: (budget.rows_written as f64 * factor) as u64,
                    wall_ms: (budget.wall_ms as f64 * factor) as u64,
                    sql_rows_read: 0,
                    sql_rows_written: 0,
                    sql_elapsed_ms: 0,
                    statement_budget: budget.statements,
                    read_budget: budget.rows_read,
                    write_budget: budget.rows_written,
                    wall_budget: budget.wall_ms,
                    over_budget: factor > 1.0,
                    over_wall: factor > 1.0,
                    log: Vec::new(),
                }
            })
            .collect(),
    }
}

/// Every lane at `scale(lane)` of its CPU budget.
pub(super) fn fixture_cpu(scale: impl Fn(&str) -> f64) -> WorkerCpuReport {
    WorkerCpuReport {
        sampling_interval_us: 100,
        idle_window_ms: 3000,
        idle_cpu_ms: 0.0,
        rows: WORKER_CPU_BUDGETS
            .iter()
            .map(|budget| {
                let cpu_ms = budget.cpu_ms * scale(budget.lane);
                WorkerCpuRow {
                    lane: budget.lane.to_owned(),
                    events_per_round: 20,
                    rounds_cpu_ms: vec![cpu_ms],
                    cpu_ms,
                    budget_ms: budget.cpu_ms,
                    over_budget: budget.over_budget(cpu_ms),
                }
            })
            .collect(),
    }
}

/// The checked-in model — the gate tests read the real file so a
/// regenerated model is always what the fixtures are judged against.
const MODEL_TOML: &str = include_str!("../../../launch-model.toml");

pub(super) fn model() -> LaunchModel {
    LaunchModel::from_toml(MODEL_TOML).expect("model")
}
