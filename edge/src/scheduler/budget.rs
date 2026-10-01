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
    SchedulerSeedReport, SchedulerSeedRequest,
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
    ) {
        if let Ok(result) = result {
            log.lock().expect("statement log").push(StatementMetric {
                sql: sql.to_owned(),
                rows_returned: result.rows.len() as u64,
                rows_read: result.rows_read,
                rows_written: result.rows_written,
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
            let result = QuerySource::query(&mut source, &sql, &params).await;
            Self::record(&result, &log, &sql);
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
            let result = QuerySource::execute(&mut source, &sql, &params).await;
            Self::record(&result, &log, &sql);
            result
        }
    }

    fn database_size(&self) -> impl Future<Output = Result<u64, DurableDbError>> + Send {
        let inner = self.inner.clone();
        async move { inner.database_size().await }
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
    rows: Arc<Mutex<(u64, u64)>>,
}

impl<B: DbBackend> CountedBackend<B> {
    fn record(result: &Result<DbExecResult, DbError>, rows: &Arc<Mutex<(u64, u64)>>) {
        if let Ok(result) = result {
            let mut counts = rows.lock().expect("d1 counter");
            counts.0 += result.rows_read;
            counts.1 += result.rows_written;
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
            let result = inner.query(query, params).await;
            Self::record(&result, &rows);
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
            let result = inner.execute(query, params).await;
            Self::record(&result, &rows);
            result
        }
    }
}

/// Build the catalog `Db` the probe's `CatalogCoverage` consumes: the
/// `STOW_DB` binding wrapped so every statement's rows land in `rows`.
pub fn counted_d1(
    env: &skyzen::runtime::wasm::WasmEnv,
    rows: Arc<Mutex<(u64, u64)>>,
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

/// The `settings` row carrying the seed cursor —
/// `"<tag>:<n>:<queue_rows>"` with tag `reset` (n = table index),
/// `queue`, `edges_every`, `edges_thirds`, `slices`, `deps` or `done`
/// (n = 0). Each call advances it by at most one
/// [`fixture::SEED_BATCH_ROWS`] chunk, so a seed survives the
/// per-request work ceiling a whole 100k-row fixture would hit. The
/// stored shape gates reuse: a cursor for a different `queue_rows`
/// restarts the seed rather than resuming into a fixture whose rows
/// describe another shape.
const SEED_CURSOR_KEY: &str = "budget_seed";

/// Tables `reset` clears, in child-before-parent order.
const SEED_TABLES: &[&str] = &[
    "queue_dependencies",
    "published_slice_rows",
    "published_slices",
    "queue",
];

/// `POST /budget/seed` — load the fixture through the operator path:
/// `queue::migrate` first (the probe is operations work, so schema
/// discipline applies), then one cursor step. `reset` restarts the
/// cursor and clears the fixture's tables chunk by chunk. Callers loop
/// until `done`; a finished (or hand-populated) queue reports
/// `done = true, seeded = false` unless `reset` is passed.
pub async fn seed(
    db: &DurableDb,
    request: &SchedulerSeedRequest,
    settings: &queue::SchedulerSettings,
) -> Result<SchedulerSeedReport, QueueError> {
    queue::migrate(db, settings)
        .await
        .map_err(|error| QueueError::Sql(format!("probe seed migrate: {error}")))?;
    let shape = FixtureShape {
        queue_rows: request
            .queue_rows
            .unwrap_or(FixtureShape::PRODUCTION.queue_rows),
    };
    let batch = request
        .batch
        .unwrap_or(fixture::SEED_BATCH_ROWS)
        .clamp(1, fixture::SEED_BATCH_ROWS * 4);
    let fresh = format!("reset:0:{}", shape.queue_rows);
    // `reset` restarts the wipe; a cursor written for a different
    // `queue_rows` does the same — its chunks describe another shape.
    let cursor = match (request.reset.unwrap_or(false), read_seed_cursor(db).await?) {
        (false, Some(cursor)) if seed_cursor_shape(&cursor) == Some(shape.queue_rows) => cursor,
        (true, _) | (false, Some(_)) => fresh,
        (false, None) => {
            // No cursor: a populated queue is a fixture seeded before
            // cursors existed (or by hand) — report done rather than
            // double-seed; an empty one starts at the queue phase.
            if count_rows(db, "queue").await? == 0 {
                format!("queue:0:{}", shape.queue_rows)
            } else {
                format!("done:0:{}", shape.queue_rows)
            }
        }
    };
    let (next, seeded) =
        run_seed_step(db, shape, &cursor, batch, settings.dispatch_min_age_minutes).await?;
    if next != cursor {
        set_seed_cursor(db, &next).await?;
    }
    Ok(SchedulerSeedReport {
        queue_rows: count_rows(db, "queue").await?,
        dependency_rows: count_rows(db, "queue_dependencies").await?,
        slice_rows: count_rows(db, "published_slice_rows").await?,
        seeded,
        done: next.starts_with("done:"),
    })
}

/// One cursor step: clear one `reset` table chunk, or write one fixture
/// chunk and return the cursor it resumes from. `seeded` reports whether
/// the step wrote rows (a finished or empty reset step reports false).
async fn run_seed_step(
    db: &DurableDb,
    shape: FixtureShape,
    cursor: &str,
    batch: u32,
    min_age_minutes: u32,
) -> Result<(String, bool), QueueError> {
    let (tag, n, _) = parse_seed_cursor(cursor)?;
    if tag == "done" {
        return Ok((cursor.to_owned(), false));
    }
    if tag == "reset" {
        let table = SEED_TABLES
            .get(n as usize)
            .ok_or_else(|| QueueError::Sql(format!("bad seed cursor {cursor}")))?;
        // `IN (SELECT rowid … LIMIT)` rather than `DELETE … LIMIT` — the
        // latter needs a compile-time extension workerd does not ship.
        db.query(&format!(
            "DELETE FROM {table} WHERE rowid IN \
             (SELECT rowid FROM {table} LIMIT {batch})"
        ))
        .execute()
        .await
        .map_err(|error| QueueError::Sql(format!("reset {table}: {error}")))?;
        let remaining = count_rows(db, table).await?;
        let next = if remaining == 0 {
            if (n as usize) + 1 < SEED_TABLES.len() {
                format!("reset:{}:{}", n + 1, shape.queue_rows)
            } else {
                format!("queue:0:{}", shape.queue_rows)
            }
        } else {
            cursor.to_owned()
        };
        return Ok((next, true));
    }
    let phase = parse_seed_phase(tag)
        .ok_or_else(|| QueueError::Sql(format!("bad seed cursor {cursor}")))?;
    let (next_phase, next_n, done) =
        fixture::seed_batch(db, shape, phase, n, batch, min_age_minutes).await?;
    let next_tag = if done {
        "done"
    } else {
        seed_phase_tag(next_phase)
    };
    Ok((format!("{next_tag}:{next_n}:{}", shape.queue_rows), true))
}

/// The phase tag of a seed cursor value.
const fn seed_phase_tag(phase: fixture::SeedPhase) -> &'static str {
    match phase {
        fixture::SeedPhase::Queue => "queue",
        fixture::SeedPhase::EdgesEvery => "edges_every",
        fixture::SeedPhase::EdgesThirds => "edges_thirds",
        fixture::SeedPhase::Slices => "slices",
        fixture::SeedPhase::DepsMet => "deps",
    }
}

/// The inverse of [`seed_phase_tag`].
fn parse_seed_phase(tag: &str) -> Option<fixture::SeedPhase> {
    match tag {
        "queue" => Some(fixture::SeedPhase::Queue),
        "edges_every" => Some(fixture::SeedPhase::EdgesEvery),
        "edges_thirds" => Some(fixture::SeedPhase::EdgesThirds),
        "slices" => Some(fixture::SeedPhase::Slices),
        "deps" => Some(fixture::SeedPhase::DepsMet),
        _ => None,
    }
}

/// `"<tag>:<n>:<queue_rows>"` → its parts; every cursor variant carries
/// the shape it was seeded with.
fn parse_seed_cursor(cursor: &str) -> Result<(&str, u32, u32), QueueError> {
    let bad = || QueueError::Sql(format!("bad seed cursor {cursor}"));
    let mut parts = cursor.splitn(3, ':');
    let (tag, n, rows) = (
        parts.next().ok_or_else(bad)?,
        parts.next().ok_or_else(bad)?,
        parts.next().ok_or_else(bad)?,
    );
    Ok((
        tag,
        n.parse().map_err(|_| bad())?,
        rows.parse().map_err(|_| bad())?,
    ))
}

/// The `queue_rows` a cursor was written for, if it parses.
fn seed_cursor_shape(cursor: &str) -> Option<u32> {
    parse_seed_cursor(cursor).ok().map(|(_, _, rows)| rows)
}

async fn read_seed_cursor(db: &DurableDb) -> Result<Option<String>, QueueError> {
    db.query(&format!(
        "SELECT value FROM settings WHERE key = '{SEED_CURSOR_KEY}'"
    ))
    .fetch_scalar_optional::<String>()
    .await
    .map_err(|error| QueueError::Sql(format!("read seed cursor: {error}")))
}

async fn set_seed_cursor(db: &DurableDb, cursor: &str) -> Result<(), QueueError> {
    db.query(&format!(
        "INSERT INTO settings (key, value) VALUES ('{SEED_CURSOR_KEY}', ?) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value"
    ))
    .bind(cursor.to_owned())
    .execute()
    .await
    .map_err(|error| QueueError::Sql(format!("write seed cursor: {error}")))?;
    Ok(())
}

async fn count_rows(db: &DurableDb, table: &str) -> Result<u64, QueueError> {
    db.query(&format!("SELECT COUNT(*) AS n FROM {table}"))
        .fetch_scalar::<i64>()
        .await
        .map(|n| n.max(0).cast_unsigned())
        .map_err(|error| QueueError::Sql(format!("count {table}: {error}")))
}

/// Restores the seeded queue the drives are calibrated on — outside
/// the measured window, the same precedent as the installation-token
/// seed. Every task the lanes and the probe itself insert carries a
/// content-derived `task_id` (`crate-version-hash-target-rustc`), while
/// seeded rows are `printf('%064x', n)`, so `task_id LIKE '%-%'`
/// isolates exactly the rows a run added — deleting them returns the
/// queue to the seeded shape every probe measures. Two surfaces would
/// decay without it:
///
/// - `POST /admin/enqueue (trusted)` measures the batch's insert path
///   (`resubmit` measures its resync) — left behind, the batch's tasks
///   persist and the next probe prices a 31-edge `NOT EXISTS` rescan
///   (~500 reads) where the budget is calibrated on an insert.
/// - `POST /tasks/complete-run` lands only on a live in-flight row, and
///   the fixture's is spent: an earlier probe on this queue already
///   completed it, or the drive's churn did — the seeded dep graph also
///   names in-flight rows, so the pass's shape repair resurrects any of
///   them the moment they complete. The target is re-marked `running`
///   with a fresh attempt so every probe measures a real completion.
async fn rearm_fixture(db: &DurableDb, shape: FixtureShape) -> Result<(), QueueError> {
    for statement in [
        "DELETE FROM queue_dependencies WHERE task_id LIKE '%-%'",
        "DELETE FROM queue WHERE task_id LIKE '%-%'",
    ] {
        db.query(statement)
            .execute()
            .await
            .map_err(|error| QueueError::Sql(format!("re-arm inserted rows: {error}")))?;
    }
    db.query(
        "UPDATE queue \
         SET status = 'running', attempt = attempt + 1, updated_at = datetime('now') \
         WHERE task_id = printf('%064x', ?)",
    )
    .bind(i64::from(shape.running_row()))
    .execute()
    .await
    .map_err(|error| QueueError::Sql(format!("re-arm complete-run target: {error}")))?;
    Ok(())
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
    let ctx = drives::DriveContext::worker(env).map_err(QueueError::Sql)?;
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
    let queue_rows = count_rows(db, "queue").await?;
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
        queue_rows: read_seed_cursor(db)
            .await?
            .and_then(|cursor| seed_cursor_shape(&cursor))
            .unwrap_or_else(|| {
                u32::try_from(queue_rows.min(u64::from(u32::MAX))).unwrap_or(u32::MAX)
            }),
    };
    rearm_fixture(db, shape).await?;
    let log = Arc::new(Mutex::new(Vec::new()));
    let metered = DurableDb::new(MeteredBackend {
        inner: db.clone(),
        log: log.clone(),
    });
    let mut rows = Vec::with_capacity(drives::DRIVES.len());
    let mut over_budget = false;
    for drive in drives::DRIVES {
        log.lock().expect("statement log").clear();
        let d1_before = ctx.d1_counts();
        let started_ms = js_sys::Date::now();
        (drive.run)(&metered, shape, &settings, &ctx)
            .await
            .map_err(|error| QueueError::Sql(format!("drive {}: {error}", drive.name)))?;
        // `Date::now()` is milliseconds well below 2^53; the delta is
        // exactly representable and non-negative.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let wall_ms = (js_sys::Date::now() - started_ms).max(0.0) as u64;
        let (d1_rows_read, d1_rows_written) = ctx.d1_counts();
        let statements = std::mem::take(&mut *log.lock().expect("statement log"));
        let totals = (
            statements.len() as u64,
            statements.iter().map(|s| s.rows_read).sum::<u64>(),
            statements.iter().map(|s| s.rows_written).sum::<u64>(),
        );
        let budget = budget_of(drive.name)?;
        let over = totals.0 > budget.statements
            || totals.1 > budget.rows_read
            || totals.2 > budget.rows_written
            || wall_ms > budget.wall_ms;
        over_budget |= over;
        rows.push(SchedulerBudgetRow {
            name: drive.name.to_owned(),
            statements: totals.0,
            rows_read: totals.1,
            rows_written: totals.2,
            wall_ms,
            statement_budget: budget.statements,
            read_budget: budget.rows_read,
            write_budget: budget.rows_written,
            wall_budget: budget.wall_ms,
            d1_rows_read: d1_rows_read.saturating_sub(d1_before.0),
            d1_rows_written: d1_rows_written.saturating_sub(d1_before.1),
            over_budget: over,
            log: statements
                .into_iter()
                .map(|metric| SchedulerBudgetStatement {
                    sql: metric.sql,
                    rows_returned: metric.rows_returned,
                    rows_read: metric.rows_read,
                    rows_written: metric.rows_written,
                })
                .collect(),
        });
    }
    Ok(SchedulerBudgetReport {
        queue_rows,
        schema_version,
        dispatch_limit,
        claimed_tasks: ctx.claims(),
        rows,
        over_budget,
    })
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
