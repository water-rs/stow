//! The workerd half of the stow#433 cost gate — the numbers that gate a
//! merge. `POST /budget/seed` loads the production-shaped fixture into
//! this object's store and graph through the same `DurableDb` request
//! code uses;
//! `POST /budget` replays every entry of [`crate::scheduler::drives`]
//! under a metering backend and returns the real `rowsRead`/`rowsWritten`
//! cursor counters per drive — the units Cloudflare bills the Durable
//! Object on, including the index rows and trigger writes `changes()`
//! cannot see.
//!
//! Both routes answer only when the deploy carries a
//! `STOW_SCHEDULER_BUDGET=1` var — the mock stack sets it in
//! `Skyzen.mock.toml`; production never does, so they 404 there.

use std::future::Future;
use std::sync::{Arc, Mutex};

use skyzen_services::durable::{DurableDb, DurableDbBackend, DurableDbError};
use skyzen_services::sql::{DbExecResult, DbValue, QuerySource};
use stow_types::api::{
    SchedulerBudgetReport, SchedulerBudgetRequest, SchedulerBudgetRow, SchedulerBudgetStatement,
};

use super::fixture::FixtureShape;
use super::graph::GraphCell;
use super::{drives, fixture, queue};
use crate::errors::QueueError;
use stow_types::do_budgets::{DO_BUDGETS, DriveBudget};

/// The binding that unlocks the probe — a deploy var, never a secret.
pub const BUDGET_PROBE_BINDING: &str = "STOW_SCHEDULER_BUDGET";

/// One statement's counters, recorded as it returns.
struct StatementMetric {
    sql: String,
    rows_returned: u64,
    rows_read: u64,
    rows_written: u64,
    /// The statement's own awaited wall — timed around the inner
    /// `query`/`execute` on wasm, `0` on host.
    elapsed_ms: u64,
}

/// `Date.now()` under wasm; `0.0` on host — the host lane gates SQL
/// counts, not timing, so it never pays the clock read.
#[cfg(target_arch = "wasm32")]
pub(super) fn clock_ms() -> f64 {
    js_sys::Date::now()
}

/// The host clock is always zero — `elapsed_ms` is a probe-only
/// measurement and host builds must not pretend timing exists.
#[cfg(not(target_arch = "wasm32"))]
pub(super) fn clock_ms() -> f64 {
    0.0
}

/// A `DurableDbBackend` that forwards to another `DurableDb` and logs
/// each statement's real cursor counters. `DbExecResult` already carries
/// `rowsRead`/`rowsWritten` on every call — the queue code drops them,
/// so the meter lives where the result still exists: inside the backend.
#[derive(Clone)]
struct MeteredBackend {
    inner: DurableDb,
    log: Arc<Mutex<Vec<StatementMetric>>>,
}

impl MeteredBackend {
    fn record(
        result: &Result<DbExecResult, DurableDbError>,
        log: &Arc<Mutex<Vec<StatementMetric>>>,
        sql: &str,
        started_ms: f64,
    ) {
        if let Ok(result) = result {
            // `Date::now()` is milliseconds well below 2^53; the delta
            // is exactly representable and non-negative.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let elapsed_ms = (clock_ms() - started_ms).max(0.0) as u64;
            log.lock().expect("statement log").push(StatementMetric {
                sql: sql.to_owned(),
                rows_returned: result.rows.len() as u64,
                rows_read: result.rows_read,
                rows_written: result.rows_written,
                elapsed_ms,
            });
        }
    }
}

impl DurableDbBackend for MeteredBackend {
    fn query(
        &self,
        query: &str,
        params: &[DbValue],
    ) -> impl Future<Output = Result<DbExecResult, DurableDbError>> + Send {
        let inner = self.inner.clone();
        let log = self.log.clone();
        let sql = query.to_owned();
        let params = params.to_vec();
        async move {
            let mut source = &inner;
            let started_ms = clock_ms();
            let result = QuerySource::query(&mut source, &sql, &params).await;
            Self::record(&result, &log, &sql, started_ms);
            result
        }
    }

    fn execute(
        &self,
        query: &str,
        params: &[DbValue],
    ) -> impl Future<Output = Result<DbExecResult, DurableDbError>> + Send {
        let inner = self.inner.clone();
        let log = self.log.clone();
        let sql = query.to_owned();
        let params = params.to_vec();
        async move {
            let mut source = &inner;
            let started_ms = clock_ms();
            let result = QuerySource::execute(&mut source, &sql, &params).await;
            Self::record(&result, &log, &sql, started_ms);
            result
        }
    }

    fn database_size(&self) -> impl Future<Output = Result<u64, DurableDbError>> + Send {
        let inner = self.inner.clone();
        async move { inner.database_size().await }
    }

    fn sync(&self) -> impl Future<Output = Result<(), DurableDbError>> + Send {
        let inner = self.inner.clone();
        async move { inner.sync().await }
    }
}

fn budget_of(name: &str) -> Result<&'static DriveBudget, QueueError> {
    DO_BUDGETS
        .iter()
        .find(|budget| budget.name == name)
        .ok_or_else(|| QueueError::Invariant(format!("{name} has no workerd budget entry")))
}

/// `POST /budget` — replay every drive under the metering backend and
/// return the per-route totals against [`DO_BUDGETS`]. The drive list is
/// the host gate's own, so the two harnesses measure the same request
/// surface. `request.dispatch_limit` overrides the deploy's dispatch cap
/// for the pass: the mock carries a tiny cap for its own stability, and
/// a pass that cannot claim measures nothing the gate can price.
pub async fn run(
    db: &DurableDb,
    graph: &GraphCell,
    settings: &queue::SchedulerSettings,
    env: &skyzen::runtime::wasm::WasmEnv,
    alarm: &skyzen_services::durable::Alarm,
    request: &SchedulerBudgetRequest,
) -> Result<SchedulerBudgetReport, QueueError> {
    let mut settings = *settings;
    if let Some(limit) = request.dispatch_limit {
        settings.dispatch = queue::Dispatch::from_max_concurrent_jobs(limit);
    }
    let dispatch_limit = match settings.dispatch {
        queue::Dispatch::Limited(limit) => u64::from(limit.get()),
        queue::Dispatch::Paused => 0,
    };
    // The drives address nodes positionally inside the layout the seed
    // wrote; the seed record is the shape, and a store nobody seeded
    // has none to measure.
    let queue_rows = fixture::seeded_rows(db).await?.ok_or_else(|| {
        QueueError::Invariant("no fixture was seeded — seed before measuring".to_owned())
    })?;
    let shape = FixtureShape { queue_rows };
    // Every run starts from the canonical graph: reseeding restores
    // what earlier runs, passes and the callback lane moved.
    fixture::seed(db, graph, shape, super::object::now_ms()).await?;
    let ctx = drives::DriveContext::worker(env, graph.clone(), alarm);
    // Seed the cached installation token once, outside any measured
    // window: the probe dispatches to the local-CI endpoint, so no real
    // credential exists — without it the pass drive's credential step
    // would try a GitHub mint instead of the production cached-token
    // read it is meant to price.
    graph.tokens().store(crate::github_app::InstallationToken {
        token: "stow-budget-probe".to_owned(),
        expires_at: "2099-01-01T00:00:00Z".to_owned(),
    });
    let log = Arc::new(Mutex::new(Vec::new()));
    let metered = DurableDb::new(MeteredBackend {
        inner: db.clone(),
        log: log.clone(),
    });
    let mut rows = Vec::with_capacity(drives::DRIVES.len());
    let mut over_budget = false;
    for drive in drives::DRIVES {
        let row = run_drive(drive, db, &metered, shape, &settings, &ctx, &log).await?;
        over_budget |= row.over_budget;
        rows.push(row);
    }
    Ok(SchedulerBudgetReport {
        queue_rows: u64::from(queue_rows),
        dispatch_limit,
        claimed_tasks: ctx.claims(),
        rows,
        over_budget,
    })
}

/// The probe's per-drive measurements, fed one [`drives::PhaseMark`]
/// at a time by [`drives::drive_lifecycle`]: the measured wall opens
/// at the run's starting mark — the fixture barrier has already
/// resolved, so every earlier write was confirmed durable — and
/// closes at the in-window barrier's finished mark, so the drive's
/// own write confirmation lands in the reported number. Statement
/// deltas bracket the same window. The wall is a reported
/// measurement, never a gate (stow#567): in this lane it is mostly the
/// runner's own storage latency, not the code's cost.
struct WindowMeasure<'a> {
    drive: &'a str,
    log: &'a Arc<Mutex<Vec<StatementMetric>>>,
    phase_started_ms: f64,
    started_ms: f64,
    wall_ms: u64,
    statements: Vec<StatementMetric>,
}

impl WindowMeasure<'_> {
    const fn new<'a>(
        drive: &'a str,
        log: &'a Arc<Mutex<Vec<StatementMetric>>>,
    ) -> WindowMeasure<'a> {
        WindowMeasure {
            drive,
            log,
            phase_started_ms: 0.0,
            started_ms: 0.0,
            wall_ms: 0,
            statements: Vec::new(),
        }
    }

    fn mark(&mut self, mark: drives::PhaseMark) {
        match mark {
            drives::PhaseMark::Starting(phase) => {
                if phase == drives::LifecyclePhase::Run {
                    self.started_ms = clock_ms();
                } else {
                    self.phase_started_ms = clock_ms();
                }
            }
            drives::PhaseMark::Finished(phase) => match phase {
                drives::LifecyclePhase::Setup | drives::LifecyclePhase::Cleanup => {
                    phase_trace(self.drive, phase.name(), self.phase_started_ms);
                }
                drives::LifecyclePhase::PreSync => {
                    phase_trace(self.drive, phase.name(), self.phase_started_ms);
                    self.log.lock().expect("statement log").clear();
                }
                drives::LifecyclePhase::Run => {}
                drives::LifecyclePhase::PostSync => {
                    // `Date::now()` is milliseconds well below 2^53;
                    // the delta is exactly representable and
                    // non-negative.
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    {
                        self.wall_ms = (clock_ms() - self.started_ms).max(0.0) as u64;
                    }
                    // The "run" trace brackets the whole measured
                    // window — the pass plus its in-window barrier.
                    phase_trace(self.drive, "run", self.started_ms);
                    phase_trace(self.drive, phase.name(), self.phase_started_ms);
                    self.statements = std::mem::take(&mut *self.log.lock().expect("statement log"));
                }
            },
        }
    }
}

/// The report row a finished window produces, or the budget table's
/// own error.
fn budget_row(drive: &str, measure: WindowMeasure) -> Result<SchedulerBudgetRow, String> {
    let totals = (
        measure.statements.len() as u64,
        measure.statements.iter().map(|s| s.rows_read).sum::<u64>(),
        measure
            .statements
            .iter()
            .map(|s| s.rows_written)
            .sum::<u64>(),
    );
    match budget_of(drive) {
        Err(error) => Err(format!("budget {drive}: {error}")),
        Ok(budget) => Ok(SchedulerBudgetRow {
            name: drive.to_owned(),
            statements: totals.0,
            rows_read: totals.1,
            rows_written: totals.2,
            wall_ms: measure.wall_ms,
            statement_budget: budget.statements,
            read_budget: budget.rows_read,
            write_budget: budget.rows_written,
            wall_budget: budget.wall_ms,
            sql_rows_read: 0,
            sql_rows_written: 0,
            sql_elapsed_ms: 0,
            over_budget: budget.over_budget(totals.0, totals.1, totals.2),
            // Reported, never gated (stow#567): the local lane's wall
            // is mostly the in-window `db.sync()` durability barrier —
            // runner storage latency, not the code's cost.
            over_wall: budget.over_wall(measure.wall_ms),
            log: measure
                .statements
                .into_iter()
                .map(|metric| SchedulerBudgetStatement {
                    sql: metric.sql,
                    rows_returned: metric.rows_returned,
                    rows_read: metric.rows_read,
                    rows_written: metric.rows_written,
                    elapsed_ms: metric.elapsed_ms,
                })
                .collect(),
        }),
    }
}

/// One drive's unmetered hooks plus its metered pass, yielding the
/// budget row the report compares against [`DO_BUDGETS`]. The phase
/// ordering and error retention live in [`drives::drive_lifecycle`] —
/// shared with the host gate — while [`WindowMeasure`] owns the
/// probe's measurements.
async fn run_drive(
    drive: &drives::Drive,
    db: &DurableDb,
    metered: &DurableDb,
    shape: FixtureShape,
    settings: &queue::SchedulerSettings,
    ctx: &drives::DriveContext,
    log: &Arc<Mutex<Vec<StatementMetric>>>,
) -> Result<SchedulerBudgetRow, QueueError> {
    let mut measure = WindowMeasure::new(drive.name, log);
    let outcome = drives::drive_lifecycle(drive, db, metered, shape, settings, ctx, &mut |mark| {
        measure.mark(mark);
    })
    .await;
    if let Err(error) = outcome.setup {
        return Err(QueueError::Sql(format!(
            "drive {} setup: {error}",
            drive.name
        )));
    }
    // Every failure the measured window produced rides together — a
    // run error never swallows either barrier's own.
    let failures: Vec<String> = [&outcome.pre_sync, &outcome.run, &outcome.post_sync]
        .into_iter()
        .filter_map(|phase| {
            phase
                .as_ref()
                .and_then(|result| result.as_ref().err().cloned())
        })
        .collect();
    let result = if failures.is_empty() {
        budget_row(drive.name, measure)
    } else {
        Err(format!("drive {}: {}", drive.name, failures.join("; ")))
    };
    let cleanup_result = match &outcome.cleanup {
        Some(Err(error)) => Err(format!("drive {} cleanup: {error}", drive.name)),
        _ => Ok(()),
    };
    match (result, cleanup_result) {
        (Ok(row), Ok(())) => Ok(row),
        (Ok(_), Err(cleanup_error)) => Err(QueueError::Sql(cleanup_error)),
        (Err(run_error), Ok(())) => Err(QueueError::Sql(run_error)),
        // Both failed — report the drive's own error first, the
        // cleanup's second, so neither diagnostic is lost.
        (Err(run_error), Err(cleanup_error)) => Err(QueueError::Sql(format!(
            "{run_error}; cleanup also failed: {cleanup_error}"
        ))),
    }
}

/// Probe-only phase timing: emits one synchronous `tracing` line per
/// `run_drive` boundary — drive name, phase (`setup`/`pre_sync`/`run`/`post_sync`/`cleanup`)
/// and the phase's `Date::now` elapsed — so the native wrangler
/// persisted log locates fixture setup and cleanup separately from
/// metered work. No I/O and no awaits: the line is pure synchronous
/// logging, so it cannot refresh the worker clock, flush the storage
/// output gate, or alter the span it measures. Durations are `0` on
/// host (the host lane gates SQL counts only).
fn phase_trace(drive: &str, phase: &str, phase_started_ms: f64) {
    if clock_ms() != 0.0 {
        tracing::info!(
            "budget phase drive={drive} phase={phase} elapsed_ms={}",
            clock_ms() - phase_started_ms
        );
    }
}

#[cfg(test)]
mod tests {
    /// Mock-only deploy variables must never ship in the production
    /// manifest — `edge/Skyzen.toml`'s `[cloudflare.vars]` are the only
    /// reach the deploy has. `STOW_SCHEDULER_BUDGET` there would answer
    /// the probe routes, `STOW_LOCAL_CI_URL` would redirect every
    /// dispatch pass to a loopback dispatcher that does not exist, and
    /// `STOW_COST_BUDGET_MULTIPLIER` would inflate the self-meter the
    /// dispatch freeze reads. The `*_SECRET`/`CF_ANALYTICS_TOKEN` names
    /// are `[[secret]]` bindings in production; a plaintext var of the
    /// same name is the secret checked into the manifest. The mock
    /// manifest (`Skyzen.mock.toml`) is the one place any of these may
    /// be set.
    const MOCK_ONLY_VARS: &[&str] = &[
        "STOW_SCHEDULER_BUDGET",
        "STOW_LOCAL_CI_URL",
        "STOW_STATS_SQL_URL",
        "STOW_GITHUB_API_URL",
        "STOW_COST_BUDGET_MULTIPLIER",
        "STOW_POW_CHALLENGE_SECRET",
        "STOW_GITHUB_WEBHOOK_SECRET",
        "TURNSTILE_SECRET_KEY",
        "CF_ANALYTICS_TOKEN",
    ];

    #[test]
    fn production_manifest_carries_no_mock_only_vars() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Skyzen.toml");
        let doc: toml::Value = std::fs::read_to_string(&manifest)
            .expect("read edge/Skyzen.toml")
            .parse()
            .expect("edge/Skyzen.toml parses");
        let vars = doc
            .get("cloudflare")
            .and_then(|cloudflare| cloudflare.get("vars"))
            .and_then(|vars| vars.as_table())
            .expect("edge/Skyzen.toml has a [cloudflare.vars] table");
        for name in MOCK_ONLY_VARS {
            assert!(
                !vars.contains_key(name),
                "edge/Skyzen.toml must not set {name} — it is mock-only",
            );
        }
    }
}
