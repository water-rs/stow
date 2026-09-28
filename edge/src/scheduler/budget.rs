//! The workerd half of the stow#433 cost gate — the numbers that gate a
//! merge. `POST /budget/seed` loads the production-shaped fixture into
//! this object's SQLite through the same `DurableDb` request code uses;
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
    SchedulerBudgetReport, SchedulerBudgetRow, SchedulerBudgetStatement, SchedulerSeedReport,
    SchedulerSeedRequest,
};

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

/// One probe budget row — statements and the real cursor counters. These
/// are the numbers that gate a merge: each was measured on the 100k
/// fixture under workerd and carries ~2× headroom. A drive that goes
/// queue-size-proportional exceeds its row by orders of magnitude, not
/// by slack.
struct DriveBudget {
    name: &'static str,
    statements: u64,
    rows_read: u64,
    rows_written: u64,
}

/// The workerd budget table — the same rows the host gate carries,
/// measured in the units Cloudflare bills. Filled from the harness's
/// reported measurements; a regression fails `stow-admin scheduler
/// budget` nonzero.
const DO_BUDGETS: &[DriveBudget] = &[
    DriveBudget {
        name: "GET /status",
        statements: 4,
        rows_read: 100,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /admin/status",
        statements: 8,
        rows_read: 8_000,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks",
        statements: 3,
        rows_read: 2_000,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks?status=failed",
        statements: 3,
        rows_read: 2_000,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks?status=pending",
        statements: 3,
        rows_read: 2_000,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks?status=blocked",
        statements: 3,
        rows_read: 5_000,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks?target=…",
        statements: 3,
        rows_read: 2_000,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks?crate=…",
        statements: 3,
        rows_read: 600,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks?older_than=86400",
        statements: 3,
        rows_read: 2_000,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks?task_ids=…",
        statements: 3,
        rows_read: 100,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks/status (batch)",
        statements: 4,
        rows_read: 2_500,
        rows_written: 0,
    },
    DriveBudget {
        name: "GET /tasks/{id}",
        statements: 6,
        rows_read: 2_500,
        rows_written: 0,
    },
    DriveBudget {
        name: "POST /runs/{id}",
        statements: 3,
        rows_read: 60,
        rows_written: 40,
    },
    DriveBudget {
        name: "POST /builds/complete",
        statements: 8,
        rows_read: 200,
        rows_written: 200,
    },
    DriveBudget {
        name: "POST /tasks/retry",
        statements: 4,
        rows_read: 200,
        rows_written: 100,
    },
    DriveBudget {
        name: "POST /tasks/cancel",
        statements: 4,
        rows_read: 200,
        rows_written: 100,
    },
    DriveBudget {
        name: "POST /tasks/promote",
        statements: 4,
        rows_read: 200,
        rows_written: 100,
    },
    DriveBudget {
        name: "POST /tasks/purge",
        statements: 4,
        rows_read: 200,
        rows_written: 100,
    },
    DriveBudget {
        // The pending-depth check reads the trigger-maintained
        // `queue_status_counts` row — a handful of rows at any queue
        // size. The human-lane position walk is bounded by the lane's
        // depth, held at `FixtureShape::HUMAN_LANE_ROWS` across sizes.
        name: "POST /enqueue (untrusted)",
        statements: 4,
        rows_read: 2_200,
        rows_written: 10,
    },
    DriveBudget {
        name: "POST /admin/enqueue (trusted)",
        statements: 16,
        rows_read: 300,
        rows_written: 400,
    },
    DriveBudget {
        name: "POST /admin/enqueue (resubmit)",
        statements: 16,
        rows_read: 1_600,
        rows_written: 100,
    },
    DriveBudget {
        name: "POST /index/published (full)",
        statements: 8,
        rows_read: 500,
        rows_written: 800,
    },
    DriveBudget {
        name: "POST /index/published (delta)",
        statements: 8,
        rows_read: 700,
        rows_written: 500,
    },
    // The claim pages at `2 × open slots` and the coverage oracle
    // sees one lookup per page: the pass's read is bounded by the
    // dispatch cap plus the fixed probes, never by the frontier.
    DriveBudget {
        name: "alarm pass",
        statements: 90,
        rows_read: 800,
        rows_written: 700,
    },
];

fn budget_of(name: &str) -> &'static DriveBudget {
    DO_BUDGETS
        .iter()
        .find(|budget| budget.name == name)
        .unwrap_or_else(|| panic!("{name} has no workerd budget entry"))
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

/// `POST /budget` — replay every drive under the metering backend and
/// return the per-route totals against [`DO_BUDGETS`]. The drive list is
/// the host gate's own, so the two harnesses measure the same request
/// surface.
pub async fn run(
    db: &DurableDb,
    settings: &queue::SchedulerSettings,
) -> Result<SchedulerBudgetReport, QueueError> {
    let queue_rows = count_rows(db, "queue").await?;
    let schema_version: i64 = db
        .query("SELECT version FROM scheduler_schema_version WHERE id = 1")
        .fetch_scalar::<i64>()
        .await
        .map_err(|error| QueueError::Sql(format!("schema version: {error}")))?;
    let shape = FixtureShape {
        queue_rows: u32::try_from(queue_rows.min(u64::from(u32::MAX))).unwrap_or(u32::MAX),
    };
    let log = Arc::new(Mutex::new(Vec::new()));
    let metered = DurableDb::new(MeteredBackend {
        inner: db.clone(),
        log: log.clone(),
    });
    let mut rows = Vec::with_capacity(drives::DRIVES.len());
    let mut over_budget = false;
    for drive in drives::DRIVES {
        log.lock().expect("statement log").clear();
        (drive.run)(&metered, shape, settings)
            .await
            .map_err(|error| QueueError::Sql(format!("drive {}: {error}", drive.name)))?;
        let statements = std::mem::take(&mut *log.lock().expect("statement log"));
        let totals = (
            statements.len() as u64,
            statements.iter().map(|s| s.rows_read).sum::<u64>(),
            statements.iter().map(|s| s.rows_written).sum::<u64>(),
        );
        let budget = budget_of(drive.name);
        let over = totals.0 > budget.statements
            || totals.1 > budget.rows_read
            || totals.2 > budget.rows_written;
        over_budget |= over;
        rows.push(SchedulerBudgetRow {
            name: drive.name.to_owned(),
            statements: totals.0,
            rows_read: totals.1,
            rows_written: totals.2,
            statement_budget: budget.statements,
            read_budget: budget.rows_read,
            write_budget: budget.rows_written,
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
        rows,
        over_budget,
    })
}

#[cfg(test)]
mod tests {
    /// The budget probe binding must never ship in the production
    /// manifest — `edge/Skyzen.toml`'s `[cloudflare.vars]` are the only
    /// reach the deploy has, and `STOW_SCHEDULER_BUDGET` there would
    /// answer the probe routes in production. The mock manifest
    /// (`Skyzen.mock.toml`) is the one place it may be set.
    #[test]
    fn production_manifest_carries_no_budget_probe() {
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
        assert!(
            !vars.contains_key(super::BUDGET_PROBE_BINDING),
            "edge/Skyzen.toml must not set {} — the budget probe is mock-only",
            super::BUDGET_PROBE_BINDING,
        );
    }
}
