//! `stow-admin traffic-cost verdict` — the Traffic cost test's verdict
//! over what the run measured (stow#452, stow#772).
//!
//! It reads the scheduler budget reports at both fixture sizes and the
//! report re-measured after the peak drive, and fails on:
//!
//! - any drive over its row budget in any report (statements, rows read,
//!   rows written — `DO_BUDGETS`);
//! - a drive whose rows read or written grow with the stored bulk: the
//!   large fixture's count more than 10% plus 50 rows over the small
//!   one's;
//! - a peak second whose serialized Durable Object wall exceeds half a
//!   second, priced from the small report and from the post-load report.
//!
//! These are the checks the run itself can answer. What the month costs
//! against the Cloudflare allowances — user traffic plus the preheat
//! waves and resubmits — is `project.rs`, run by the release gate's own
//! job once the Preheat cost report exists.

use std::path::PathBuf;

use clap::Args;
use stow_types::api::SchedulerBudgetReport;
use stow_types::launch_model::LaunchModel;
use stow_types::stow_error;

use super::project::peak_serialized_s;
use crate::render::{Output, Table, emit};

/// The verdict — `stow-admin traffic-cost verdict`.
#[derive(Debug, Args)]
pub struct VerdictArgs {
    /// The scheduler budget report on the small fixture (100k rows).
    #[arg(long)]
    pub small: PathBuf,
    /// The scheduler budget report on the large fixture (1M rows), same
    /// shape — the growth check's other side.
    #[arg(long)]
    pub large: PathBuf,
    /// The scheduler budget report re-measured after the peak drive.
    #[arg(long)]
    pub after: PathBuf,
    /// The checked-in launch model `launch-model.toml`.
    #[arg(long, default_value = "launch-model.toml")]
    pub model: PathBuf,
}

/// The issue's peak requirement: a peak-second's serialized Durable
/// Object wall must stay under half a second.
const PEAK_SERIALIZED_S_PER_S: f64 = 0.5;

/// The growth rule: a drive grows with the stored bulk when its count
/// on the large fixture exceeds the small one's by more than this
/// fraction …
const GROWTH_FRACTION: f64 = 0.1;

/// … plus this many rows.
const GROWTH_SLACK_ROWS: f64 = 50.0;

/// One drive's counts on both fixture sizes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GrowthRow {
    /// The drive.
    pub name: String,
    /// `rowsRead` on the small fixture.
    pub read_small: u64,
    /// `rowsRead` on the large fixture.
    pub read_large: u64,
    /// `rowsWritten` on the small fixture.
    pub written_small: u64,
    /// `rowsWritten` on the large fixture.
    pub written_large: u64,
    /// Whether either count grows with the stored bulk.
    pub grows: bool,
}

/// The growth check: every drive's counts on both fixtures. A drive
/// may legitimately be bounded by a held quantity — lane depth, the
/// 24 h outcome window, in-flight count, the report's own size — and
/// the fixture pins those across sizes, so only the stored bulk grows.
#[expect(clippy::cast_precision_loss, reason = "row counters fit f64 exactly")]
fn growth(
    small: &SchedulerBudgetReport,
    large: &SchedulerBudgetReport,
) -> Result<Vec<GrowthRow>, String> {
    if small.queue_rows >= large.queue_rows {
        return Err(format!(
            "the small report holds {} queue rows and the large one {} — the growth check \
             needs the small fixture first",
            small.queue_rows, large.queue_rows
        ));
    }
    let grows =
        |a: u64, b: u64| b as f64 > (a as f64).mul_add(1.0 + GROWTH_FRACTION, GROWTH_SLACK_ROWS);
    let rows: Vec<GrowthRow> = small
        .rows
        .iter()
        .map(|a| {
            let b = large
                .rows
                .iter()
                .find(|b| b.name == a.name)
                .ok_or_else(|| format!("the large report carries no row for `{}`", a.name))?;
            Ok(GrowthRow {
                name: a.name.clone(),
                read_small: a.rows_read,
                read_large: b.rows_read,
                written_small: a.rows_written,
                written_large: b.rows_written,
                grows: grows(a.rows_read, b.rows_read) || grows(a.rows_written, b.rows_written),
            })
        })
        .collect::<Result<_, String>>()?;
    if let Some(extra) = large
        .rows
        .iter()
        .find(|b| !small.rows.iter().any(|a| a.name == b.name))
    {
        return Err(format!(
            "the small report carries no row for `{}`",
            extra.name
        ));
    }
    Ok(rows)
}

/// A drive over its row budget in one of the reports.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OverBudget {
    /// Which report — `small`, `large` or `after`.
    pub report: &'static str,
    /// Its fixture size.
    pub queue_rows: u64,
    /// The drive.
    pub name: String,
}

/// Collect the over-budget rows of one report.
fn over_budget(label: &'static str, report: &SchedulerBudgetReport) -> Vec<OverBudget> {
    report
        .rows
        .iter()
        .filter(|row| row.over_budget)
        .map(|row| OverBudget {
            report: label,
            queue_rows: report.queue_rows,
            name: row.name.clone(),
        })
        .collect()
}

/// A report's serialized Durable Object wall at the model's peak rate.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeakWall {
    /// Which report — `small` or `after`.
    pub report: &'static str,
    /// Serialized wall seconds per second at peak.
    pub serialized_s_per_s: f64,
    /// Its bound.
    pub bound_s_per_s: f64,
}

/// The whole verdict.
#[derive(Debug, serde::Serialize)]
pub struct Verdict {
    /// Drives over a row budget, in any report.
    pub over_budget: Vec<OverBudget>,
    /// The growth check, row by row.
    pub growth: Vec<GrowthRow>,
    /// The peak serialized wall from the small report and from the
    /// post-load report.
    pub peak: Vec<PeakWall>,
}

impl Verdict {
    /// Every failure, one line each.
    fn failures(&self) -> Vec<String> {
        let mut failures: Vec<String> = self
            .over_budget
            .iter()
            .map(|row| {
                format!(
                    "{} report ({} rows): `{}` over its row budget",
                    row.report, row.queue_rows, row.name
                )
            })
            .collect();
        failures.extend(
            self.growth
                .iter()
                .filter(|row| row.grows)
                .map(|row| format!("`{}` grows with the stored rows", row.name)),
        );
        failures.extend(
            self.peak
                .iter()
                .filter(|wall| wall.serialized_s_per_s > wall.bound_s_per_s)
                .map(|wall| {
                    format!(
                        "{} report: peak serialized DO wall {:.3} s/s over bound {:.2} s/s",
                        wall.report, wall.serialized_s_per_s, wall.bound_s_per_s
                    )
                }),
        );
        failures
    }
}

/// Judge every input.
fn judge(
    model: &LaunchModel,
    small: &SchedulerBudgetReport,
    large: &SchedulerBudgetReport,
    after: &SchedulerBudgetReport,
) -> Result<Verdict, String> {
    let mut over = over_budget("small", small);
    over.extend(over_budget("large", large));
    over.extend(over_budget("after", after));
    let peak = |report: &'static str, budget: &SchedulerBudgetReport| {
        Ok::<_, String>(PeakWall {
            report,
            serialized_s_per_s: peak_serialized_s(model, budget)?,
            bound_s_per_s: PEAK_SERIALIZED_S_PER_S,
        })
    };
    Ok(Verdict {
        over_budget: over,
        growth: growth(small, large)?,
        peak: vec![peak("small", small)?, peak("after", after)?],
    })
}

/// Human rendering of the verdict.
fn render_verdict(verdict: &Verdict) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let mut table = Table::new(&["drive", "rows_read", "rows_written", ""]);
    for row in &verdict.growth {
        table.push([
            row.name.clone(),
            format!("{}→{}", row.read_small, row.read_large),
            format!("{}→{}", row.written_small, row.written_large),
            if row.grows { "GROWS" } else { "" }.to_owned(),
        ]);
    }
    let _ = writeln!(
        out,
        "growth check (small → large fixture):\n{}",
        table.render()
    );
    for wall in &verdict.peak {
        let _ = writeln!(
            out,
            "\npeak serialized DO wall, {} report: {:.3} s/s (bound {:.2} s/s)",
            wall.report, wall.serialized_s_per_s, wall.bound_s_per_s
        );
    }
    let failures = verdict.failures();
    if failures.is_empty() {
        let _ = writeln!(out, "\ntraffic cost: PASS");
    } else {
        let _ = writeln!(out, "\ntraffic cost: FAIL");
        for failure in &failures {
            let _ = writeln!(out, "  {failure}");
        }
    }
    out
}

/// `stow-admin traffic-cost verdict` — judge and exit nonzero on any
/// failure.
pub async fn run(args: &VerdictArgs, output: Output) -> stow_types::error::Result<()> {
    let small: SchedulerBudgetReport = super::read_json("budget report", &args.small).await?;
    let large: SchedulerBudgetReport = super::read_json("budget report", &args.large).await?;
    let after: SchedulerBudgetReport = super::read_json("budget report", &args.after).await?;
    let model = super::read_model(&args.model).await?;
    let verdict = judge(&model, &small, &large, &after).map_err(|error| stow_error!("{error}"))?;
    emit(output, &verdict, render_verdict)?;
    let failures = verdict.failures();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(stow_error!("traffic cost: {} failure(s)", failures.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::{growth, judge, render_verdict};
    use crate::traffic_cost::test_support::{fixture_report, model};

    #[test]
    fn a_healthy_run_passes() {
        let small = fixture_report(100_000, |_| 0.5);
        let large = fixture_report(1_000_000, |_| 0.5);
        let after = fixture_report(100_000, |_| 0.5);
        let verdict = judge(&model(), &small, &large, &after).expect("judge");
        let rendered = render_verdict(&verdict);
        assert!(verdict.failures().is_empty(), "{rendered}");
        assert!(rendered.contains("traffic cost: PASS"), "{rendered}");
        assert!(rendered.contains("peak serialized DO wall"), "{rendered}");
    }

    /// A drive whose rows track the stored bulk fails the growth check;
    /// one inside 10% + 50 rows passes.
    #[test]
    fn rows_that_grow_with_the_fixture_fail() {
        let small = fixture_report(100_000, |_| 0.5);
        let flat = fixture_report(
            1_000_000,
            |name| if name == "GET /status" { 0.55 } else { 0.5 },
        );
        assert!(
            growth(&small, &flat)
                .expect("growth")
                .iter()
                .all(|row| !row.grows)
        );
        let mut grown = fixture_report(1_000_000, |_| 0.5);
        let row = grown
            .rows
            .iter_mut()
            .find(|row| row.name == "GET /tasks")
            .expect("row");
        row.rows_read += 1_000;
        let rows = growth(&small, &grown).expect("growth");
        let rising: Vec<&str> = rows
            .iter()
            .filter(|row| row.grows)
            .map(|row| row.name.as_str())
            .collect();
        assert_eq!(rising, ["GET /tasks"]);
    }

    /// An over-budget row in the post-load report fails the verdict.
    #[test]
    fn an_over_budget_row_after_the_drive_fails() {
        let small = fixture_report(100_000, |_| 0.5);
        let large = fixture_report(1_000_000, |_| 0.5);
        let after = fixture_report(
            100_000,
            |name| if name == "GET /status" { 1.5 } else { 0.5 },
        );
        let verdict = judge(&model(), &small, &large, &after).expect("judge");
        let failures = verdict.failures();
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("after report") && failure.contains("GET /status")),
            "{failures:?}"
        );
    }

    /// A serialized wall past half a second per second at peak fails the
    /// verdict, from either report.
    #[test]
    fn a_serialized_wall_over_the_bound_fails() {
        let small = fixture_report(100_000, |_| 0.5);
        let large = fixture_report(1_000_000, |_| 0.5);
        // The alarm pass is priced on every dispatch: 1000× its wall
        // puts the peak second far past the bound.
        let after = fixture_report(100_000, |name| {
            if name == "alarm pass (idle)" {
                1_000.0
            } else {
                0.5
            }
        });
        let verdict = judge(&model(), &small, &large, &after).expect("judge");
        let failures = verdict.failures();
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("after report") && failure.contains("peak")),
            "{failures:?}"
        );
        assert!(
            !failures
                .iter()
                .any(|failure| failure.contains("small report") && failure.contains("peak")),
            "{failures:?}"
        );
    }

    /// The growth check needs the small fixture first.
    #[test]
    fn swapped_fixtures_are_refused() {
        let small = fixture_report(100_000, |_| 0.5);
        let large = fixture_report(1_000_000, |_| 0.5);
        let error = growth(&large, &small).expect_err("swapped fixtures must refuse");
        assert!(error.contains("small fixture first"), "{error}");
    }
}
