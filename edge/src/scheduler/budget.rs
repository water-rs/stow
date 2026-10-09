//! The workerd half of the stow#433 cost gate — the numbers that gate a
//! merge. `POST /budget/seed` loads the production-shaped fixture into
//! this object's `SQLite` through the same `DurableDb` request code uses;
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

use skyzen_cloudflare::CfD1;
use skyzen_services::durable::{DurableDb, DurableDbBackend, DurableDbError};
use skyzen_services::sql::{DbBackend, DbDialect, DbError, DbExecResult, DbValue, QuerySource};
use stow_types::api::{
    SchedulerBudgetReport, SchedulerBudgetRequest, SchedulerBudgetRow, SchedulerBudgetStatement,
};

use super::do_budgets::{DO_BUDGETS, DriveBudget};
use super::fixture::FixtureShape;
use super::{drives, fixture, queue};
use crate::errors::QueueError;

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

/// A `DbBackend` that forwards to another and accumulates each
/// statement's `DbExecResult` counters — D1's `meta.rowsRead` /
/// `rowsWritten` — into a shared pair the report reads back per drive.
/// The `DurableDb` meter can't see these: the coverage lookups a claim
/// pays are ordinary Worker D1 traffic, billed as D1 rows, not object
/// rows.
#[derive(Clone)]
pub struct CountedBackend<B> {
    inner: B,
    /// `(rows_read, rows_written, elapsed_ms)` — the trailing counter
    /// is the Σ awaited wall over the backend's own calls, so a hot
    /// drive's catalog-lookup time is attributable separately from
    /// its object-statement time.
    rows: Arc<Mutex<(u64, u64, u64)>>,
}

impl<B: DbBackend> CountedBackend<B> {
    fn record(
        result: &Result<DbExecResult, DbError>,
        rows: &Arc<Mutex<(u64, u64, u64)>>,
        started_ms: f64,
    ) {
        // One synchronous tracing line per counted call, success or
        // failure — the Σ collector keeps no per-call split.
        d1_call_trace(result.is_ok(), started_ms);
        if let Ok(result) = result {
            let mut counts = rows.lock().expect("d1 counter");
            counts.0 += result.rows_read;
            counts.1 += result.rows_written;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                counts.2 += (clock_ms() - started_ms).max(0.0) as u64;
            }
        }
    }
}

impl<B: DbBackend> DbBackend for CountedBackend<B> {
    fn dialect(&self) -> DbDialect {
        self.inner.dialect()
    }

    fn query(
        &self,
        query: &str,
        params: &[DbValue],
    ) -> impl Future<Output = Result<DbExecResult, DbError>> + Send {
        let inner = self.inner.clone();
        let rows = self.rows.clone();
        async move {
            let started_ms = clock_ms();
            let result = inner.query(query, params).await;
            Self::record(&result, &rows, started_ms);
            result
        }
    }

    fn execute(
        &self,
        query: &str,
        params: &[DbValue],
    ) -> impl Future<Output = Result<DbExecResult, DbError>> + Send {
        let inner = self.inner.clone();
        let rows = self.rows.clone();
        async move {
            let started_ms = clock_ms();
            let result = inner.execute(query, params).await;
            Self::record(&result, &rows, started_ms);
            result
        }
    }
}

/// Build the catalog `Db` the probe's `CatalogCoverage` consumes: the
/// `STOW_DB` binding wrapped so every statement's rows land in `rows`.
pub fn counted_d1(
    env: &skyzen::runtime::wasm::WasmEnv,
    rows: Arc<Mutex<(u64, u64, u64)>>,
) -> Result<skyzen_services::Db, String> {
    let inner = CfD1::from_env(env.as_js(), super::object::STOW_DB_BINDING)
        .map_err(|error| format!("load D1 binding: {error}"))?;
    Ok(skyzen_services::Db::new(CountedBackend { inner, rows }))
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
    let ctx = drives::DriveContext::worker(env, alarm).map_err(QueueError::Sql)?;
    // Seed the cached installation token once, outside any measured
    // window: the probe dispatches to the local-CI endpoint, so no real
    // credential exists — without this row the pass drive's credential
    // step would try a GitHub mint instead of the production
    // cached-token read it is meant to price.
    #[cfg(target_arch = "wasm32")]
    queue::store_github_app_token(
        db,
        &crate::github_app::InstallationToken {
            token: "stow-budget-probe".to_owned(),
            expires_at: "2099-01-01T00:00:00Z".to_owned(),
        },
    )
    .await?;
    let queue_rows = fixture::count_rows(db, "queue").await?;
    let schema_version: i64 = db
        .query("SELECT version FROM scheduler_schema_version WHERE id = 1")
        .fetch_scalar::<i64>()
        .await
        .map_err(|error| QueueError::Sql(format!("schema version: {error}")))?;
    // The drives address rows positionally inside the layout the fixture
    // wrote — `running_row`, `dep_row`, `completed_row` and friends are
    // arithmetic on that shape. A queue that has been churned since
    // seeding (admissions, enqueues, alarm traffic) has grown past it, so
    // deriving the shape from the live count shifts every boundary and
    // the drives hit rows their status predicates reject. The seed
    // cursor is the record of what was written; only a queue nobody
    // seeded falls back to the live count.
    let shape = FixtureShape {
        queue_rows: fixture::read_seed_cursor(db)
            .await?
            .and_then(|cursor| fixture::seed_cursor_shape(&cursor).ok())
            .unwrap_or_else(|| {
                u32::try_from(queue_rows.min(u64::from(u32::MAX))).unwrap_or(u32::MAX)
            }),
    };
    fixture::rearm(db, shape, settings.dispatch_min_age_minutes).await?;
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
    // The pass's claim record for the next run's re-arm — written on
    // `db` directly, so like the re-arm it lands outside the metered
    // window it exists to serve.
    fixture::record_probe_claimed(db, &ctx.claimed_ids()).await?;
    Ok(SchedulerBudgetReport {
        queue_rows,
        schema_version,
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
/// own write confirmation lands in the reported number. Statement and
/// D1 deltas bracket the same window. The wall is a reported
/// measurement, never a gate (stow#567): in this lane it is mostly the
/// runner's own storage latency, not the code's cost.
struct WindowMeasure<'a> {
    drive: &'a str,
    ctx: &'a drives::DriveContext,
    log: &'a Arc<Mutex<Vec<StatementMetric>>>,
    phase_started_ms: f64,
    started_ms: f64,
    wall_ms: u64,
    d1_before: (u64, u64, u64),
    d1_after: (u64, u64, u64),
    statements: Vec<StatementMetric>,
}

impl WindowMeasure<'_> {
    const fn new<'a>(
        drive: &'a str,
        ctx: &'a drives::DriveContext,
        log: &'a Arc<Mutex<Vec<StatementMetric>>>,
    ) -> WindowMeasure<'a> {
        WindowMeasure {
            drive,
            ctx,
            log,
            phase_started_ms: 0.0,
            started_ms: 0.0,
            wall_ms: 0,
            d1_before: (0, 0, 0),
            d1_after: (0, 0, 0),
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
                    self.d1_before = self.ctx.d1_counts();
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
                    self.d1_after = self.ctx.d1_counts();
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
            d1_rows_read: measure.d1_after.0.saturating_sub(measure.d1_before.0),
            d1_rows_written: measure.d1_after.1.saturating_sub(measure.d1_before.1),
            d1_elapsed_ms: measure.d1_after.2.saturating_sub(measure.d1_before.2),
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
    let mut measure = WindowMeasure::new(drive.name, ctx, log);
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

/// Probe-only per-call timing: one synchronous `tracing` line per
/// counted D1 operation — its own awaited elapsed and whether it
/// succeeded, never the statement's bound parameters. Same
/// synchronous-logging rule as [`phase_trace`]; silent on host, where
/// the clock is `0`.
fn d1_call_trace(ok: bool, started_ms: f64) {
    if clock_ms() != 0.0 {
        tracing::info!(
            "budget d1 call ok={ok} elapsed_ms={}",
            clock_ms() - started_ms
        );
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
