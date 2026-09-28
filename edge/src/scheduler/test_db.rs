//! Host-only [`DurableDb`] backend over an in-memory `SQLite` database, so the
//! scheduler's SQL (queue schema, eligibility predicates, lease arithmetic)
//! is exercised by unit tests instead of only the pure `plan_alarm` policy.

use std::sync::atomic::{AtomicBool, Ordering};

use skyzen_services::durable::{
    DbExecResult, DbValue, DurableDb, DurableDbBackend, DurableDbError,
};
use sqlx::{Column as _, Row as _, TypeInfo as _, ValueRef as _, sqlite::SqliteRow};

use crate::errors::QueueError;
use crate::scheduler::queue::{self, SchedulerSettings};

/// `DurableDbBackend` backed by a `sqlx` `SQLite` pool.
#[derive(Debug, Clone)]
struct SqliteBackend {
    pool: sqlx::SqlitePool,
    /// Whether DDL and PRAGMA statements pass [`check_do_statements`].
    /// Migrations are operations work — only the migrate path may issue
    /// them — so the flag is on while a migration-capable database is
    /// constructed or handed to a migration test (`memory_db_raw`), and
    /// off on every database the request paths see. A statement that
    /// creates, alters, drops or probes the schema from request code
    /// fails the test instead of slipping to production, where the DO
    /// would accept the DDL but the ops rule forbids it.
    ddl_permitted: std::sync::Arc<AtomicBool>,
}

impl SqliteBackend {
    /// Revert the backend to request-path mode — every constructor that
    /// runs the migration calls this once it has applied the schema.
    fn close_migration(&self) {
        self.ddl_permitted.store(false, Ordering::Relaxed);
    }
}

/// Open a fresh in-memory queue database with the scheduler schema applied.
///
/// `max_connections(1)` is required: `sqlite::memory:` databases are scoped to
/// a single connection, so a wider pool would hand out independent empty
/// databases.
///
/// # Errors
///
/// Returns `QueueError::Sql` if the pool cannot be opened or `migrate`
/// fails.
pub async fn memory_db() -> Result<DurableDb, QueueError> {
    let backend = memory_backend().await?;
    let db = DurableDb::new(backend.clone());
    queue::migrate(&db, &SchedulerSettings::default()).await?;
    backend.close_migration();
    Ok(db)
}

/// Open a fresh in-memory queue database with NO schema applied and the
/// DDL/PRAGMA permit still on — the migrate path's fixture: migration
/// tests write an older schema's DDL themselves before calling
/// `queue::migrate`, the only code that may issue DDL.
///
/// # Errors
///
/// Returns `QueueError::Sql` if the pool cannot be opened.
pub async fn memory_db_raw() -> Result<DurableDb, QueueError> {
    Ok(DurableDb::new(memory_backend().await?))
}

/// One statement the wrapped backend ran: the SQL text, its bound
/// parameters (so the statement can be replayed under `EXPLAIN QUERY
/// PLAN`), the rows the engine returned or wrote, and the wall time.
/// The submit-path measurements for issue #418 read this after a run to
/// report statement counts per request and per dependency edge; the
/// stow#433 cost gate reads it for statement counts, rows written,
/// result rows and query plans per route.
#[derive(Debug, Clone)]
pub struct LoggedStatement {
    /// The SQL exactly as the queue code issued it.
    pub sql: String,
    /// The parameters bound to it, in bind order.
    pub params: Vec<DbValue>,
    /// Rows the statement returned (its result cardinality — not the
    /// rows its plan touched; the plan is what bounds those).
    pub rows_read: u64,
    /// Rows the statement wrote (`changes()`/`total_changes()` per
    /// statement).
    pub rows_written: u64,
    /// Wall time on the in-memory backend — a size signal only; the
    /// budgets key on counts and plans, never on elapsed time.
    pub elapsed: std::time::Duration,
}

/// Every statement the wrapped backend ran, in order.
pub type StatementLog = std::sync::Arc<std::sync::Mutex<Vec<LoggedStatement>>>;

/// Open a fresh in-memory queue database (schema applied) whose backend
/// records every statement it executes, returning the log alongside.
///
/// # Errors
///
/// Returns `QueueError::Sql` if the pool cannot be opened or `migrate`
/// fails.
pub async fn counting_memory_db() -> Result<(DurableDb, StatementLog), QueueError> {
    let log = StatementLog::default();
    let inner = memory_backend().await?;
    let db = DurableDb::new(CountingBackend {
        inner: inner.clone(),
        log: log.clone(),
    });
    queue::migrate(&db, &SchedulerSettings::default()).await?;
    inner.close_migration();
    Ok((db, log))
}

/// [`counting_memory_db`] without closing the migration permit — for the
/// one route that legitimately issues DDL: the operator `migrate`
/// handler itself, which the stow#433 gate measures against the same
/// fixture but outside the no-DDL rule.
pub async fn counting_memory_db_raw() -> Result<(DurableDb, StatementLog), QueueError> {
    let log = StatementLog::default();
    let inner = memory_backend().await?;
    let db = DurableDb::new(CountingBackend {
        inner,
        log: log.clone(),
    });
    queue::migrate(&db, &SchedulerSettings::default()).await?;
    Ok((db, log))
}

async fn memory_backend() -> Result<SqliteBackend, QueueError> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .map_err(|error| QueueError::Sql(format!("open in-memory sqlite: {error}")))?;
    Ok(SqliteBackend {
        pool,
        ddl_permitted: std::sync::Arc::new(AtomicBool::new(true)),
    })
}

/// A `SqliteBackend` wrapper that appends every statement and its wall
/// time to a shared log before returning the real result.
#[derive(Debug, Clone)]
struct CountingBackend {
    inner: SqliteBackend,
    log: StatementLog,
}

impl CountingBackend {
    fn record(
        &self,
        sql: &str,
        params: &[DbValue],
        elapsed: std::time::Duration,
        result: &Result<DbExecResult, DurableDbError>,
    ) {
        let (rows_read, rows_written) = result
            .as_ref()
            .map_or((0, 0), |result| (result.rows_read, result.rows_written));
        self.log
            .lock()
            .expect("statement log")
            .push(LoggedStatement {
                sql: sql.to_owned(),
                params: params.to_vec(),
                rows_read,
                rows_written,
                elapsed,
            });
    }
}

impl DurableDbBackend for CountingBackend {
    async fn query(&self, query: &str, params: &[DbValue]) -> Result<DbExecResult, DurableDbError> {
        let start = std::time::Instant::now();
        let result = self.inner.query(query, params).await;
        self.record(query, params, start.elapsed(), &result);
        result
    }

    async fn execute(
        &self,
        query: &str,
        params: &[DbValue],
    ) -> Result<DbExecResult, DurableDbError> {
        let start = std::time::Instant::now();
        let result = self.inner.execute(query, params).await;
        self.record(query, params, start.elapsed(), &result);
        result
    }

    async fn database_size(&self) -> Result<u64, DurableDbError> {
        self.inner.database_size().await
    }
}

/// The PRAGMA names the Durable Object SQL authorizer accepts — the set
/// D1 documents as compatible, which the DO authorizer mirrors:
/// <https://developers.cloudflare.com/d1/sql-api/sql-statements/>
/// lists `table_list` and `table_info`, and
/// <https://developers.cloudflare.com/d1/sql-api/foreign-keys/> adds
/// `defer_foreign_keys`. `PRAGMA user_version` is explicitly
/// unsupported on DO storage:
/// <https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/>.
/// The host backend refuses what the DO refuses so a disallowed pragma
/// fails a host test instead of taking production down (stow#432).
const DO_ALLOWED_PRAGMAS: &[&str] = &["defer_foreign_keys", "table_info", "table_list"];

/// Statement heads that mutate or probe schema: the DO accepts them,
/// but the ops rule is that only the migrate route may issue them —
/// request paths and the alarm never create, alter, drop, index or
/// backfill anything (stow#432). The backend enforces it by refusing
/// them unless `ddl_permitted` is set, so host tests exercise the same
/// boundary production conventions draw.
const DDL_HEADS: &[&str] = &[
    "alter", "analyze", "attach", "create", "detach", "drop", "reindex", "vacuum",
];

/// Gate one statement string on the two boundaries the host backend
/// stands in for: the DO authorizer's pragma allowlist
/// ([`DO_ALLOWED_PRAGMAS`], applied even inside the migrate path — the
/// real DO authorizer checks the migrate handler's statements too) and
/// the ops rule that only migration code may issue DDL or pragmas
/// (`ddl_permitted`, set only while `queue::migrate` is reachable).
/// Statement heads are read after `;`; string literals and
/// `--`/`/* */` comments are skipped so a false positive cannot block a
/// statement that merely mentions the word — and an injection
/// mid-string cannot hide a real head from the check.
fn check_do_statements(sql: &str, ddl_permitted: bool) -> Result<(), DurableDbError> {
    let bytes = sql.as_bytes();
    let mut index = 0;
    let mut statement_start = true;
    while index < bytes.len() {
        match bytes[index] {
            quote @ (b'\'' | b'"' | b'`') => {
                index += 1;
                while index < bytes.len() {
                    if bytes[index] == quote {
                        // A doubled quote is an escape, not the end.
                        if bytes.get(index + 1) == Some(&quote) {
                            index += 2;
                            continue;
                        }
                        index += 1;
                        break;
                    }
                    index += 1;
                }
            }
            b'-' if bytes.get(index + 1) == Some(&b'-') => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                {
                    index += 1;
                }
                index = (index + 2).min(bytes.len());
            }
            b';' => {
                statement_start = true;
                index += 1;
            }
            byte if byte.is_ascii_whitespace() => index += 1,
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                if statement_start {
                    let head = sql[start..index].to_ascii_lowercase();
                    if head == "pragma" {
                        // The pragma name follows, after any whitespace.
                        let mut cursor = index;
                        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                            cursor += 1;
                        }
                        let name_start = cursor;
                        while cursor < bytes.len()
                            && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
                        {
                            cursor += 1;
                        }
                        let name = sql[name_start..cursor].to_ascii_lowercase();
                        if !ddl_permitted {
                            return Err(backend_error(format!(
                                "PRAGMA {name} outside the scheduler migrate route"
                            )));
                        }
                        if !DO_ALLOWED_PRAGMAS.contains(&name.as_str()) {
                            return Err(backend_error(format!(
                                "PRAGMA {name} is not supported by Durable Objects SQLite storage"
                            )));
                        }
                    } else if !ddl_permitted && DDL_HEADS.contains(&head.as_str()) {
                        return Err(backend_error(format!(
                            "{head} outside the scheduler migrate route — request code \
                             and the alarm never issue DDL"
                        )));
                    }
                }
                statement_start = false;
            }
            _ => {
                statement_start = false;
                index += 1;
            }
        }
    }
    Ok(())
}

impl DurableDbBackend for SqliteBackend {
    async fn query(&self, query: &str, params: &[DbValue]) -> Result<DbExecResult, DurableDbError> {
        check_do_statements(query, self.ddl_permitted.load(Ordering::Relaxed))?;
        let rows = bind_params(sqlx::query(sqlx::AssertSqlSafe(query)), params)
            .fetch_all(&self.pool)
            .await
            .map_err(backend_error)?;
        let rows = rows
            .iter()
            .map(row_to_json)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DbExecResult {
            rows_read: u64::try_from(rows.len()).map_err(backend_error)?,
            rows,
            rows_written: 0,
        })
    }

    async fn execute(
        &self,
        query: &str,
        params: &[DbValue],
    ) -> Result<DbExecResult, DurableDbError> {
        check_do_statements(query, self.ddl_permitted.load(Ordering::Relaxed))?;
        let result = bind_params(sqlx::query(sqlx::AssertSqlSafe(query)), params)
            .execute(&self.pool)
            .await
            .map_err(backend_error)?;
        Ok(DbExecResult {
            rows: Vec::new(),
            rows_read: 0,
            rows_written: result.rows_affected(),
        })
    }

    async fn database_size(&self) -> Result<u64, DurableDbError> {
        let page_count = pragma_i64(&self.pool, "PRAGMA page_count").await?;
        let page_size = pragma_i64(&self.pool, "PRAGMA page_size").await?;
        page_count
            .checked_mul(page_size)
            .ok_or_else(|| backend_error("sqlite database size overflow"))
    }
}

fn backend_error(error: impl std::fmt::Display) -> DurableDbError {
    DurableDbError::Backend {
        message: error.to_string(),
        source: None,
    }
}

async fn pragma_i64(pool: &sqlx::SqlitePool, sql: &str) -> Result<u64, DurableDbError> {
    let value: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .fetch_one(pool)
        .await
        .map_err(backend_error)?;
    u64::try_from(value).map_err(backend_error)
}

fn bind_params<'q>(
    query: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments>,
    params: &[DbValue],
) -> sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments> {
    let mut query = query;
    for param in params {
        query = match param {
            DbValue::Null => query.bind(Option::<String>::None),
            DbValue::Boolean(value) => query.bind(*value),
            DbValue::Integer(value) => query.bind(*value),
            DbValue::Real(value) => query.bind(*value),
            DbValue::Text(value) => query.bind(value.clone()),
            DbValue::Blob(value) => query.bind(value.clone()),
            // The richer DbValue variants bind as the text renderings the
            // Durable Object SQL backend this harness stands in for uses, so a
            // test writes the same bytes production would.
            DbValue::Timestamp(value) => query.bind(value.to_rfc3339()),
            DbValue::Uuid(value) => query.bind(value.to_string()),
            DbValue::Decimal(value) => query.bind(value.to_string()),
            DbValue::Json(value) => query.bind(value.to_string()),
        };
    }
    query
}

fn row_to_json(row: &SqliteRow) -> Result<serde_json::Value, DurableDbError> {
    let mut object = serde_json::Map::with_capacity(row.len());
    for (index, column) in row.columns().iter().enumerate() {
        object.insert(column.name().to_owned(), value_to_json(row, index)?);
    }
    Ok(serde_json::Value::Object(object))
}

/// Convert by the value's runtime storage class, not the column's declared
/// type: expression columns (`count(*)`, `CAST`, `datetime()`) declare none,
/// and `SQLite` stores whatever class the expression produced.
fn value_to_json(row: &SqliteRow, index: usize) -> Result<serde_json::Value, DurableDbError> {
    let raw = row.try_get_raw(index).map_err(backend_error)?;
    if raw.is_null() {
        return Ok(serde_json::Value::Null);
    }
    let storage_class = raw.type_info().name().to_owned();
    match storage_class.as_str() {
        "BOOLEAN" => decode_json::<bool>(row, index),
        "INTEGER" => decode_json::<i64>(row, index),
        "REAL" => decode_json::<f64>(row, index),
        "TEXT" => decode_json::<String>(row, index),
        "BLOB" => decode_json::<Vec<u8>>(row, index),
        other => Err(backend_error(format!(
            "unsupported sqlite storage class {other} in column {index}"
        ))),
    }
}

fn decode_json<'r, T>(row: &'r SqliteRow, index: usize) -> Result<serde_json::Value, DurableDbError>
where
    T: sqlx::Decode<'r, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite> + serde::Serialize,
{
    let value: T = row.try_get(index).map_err(backend_error)?;
    Ok(serde_json::json!(value))
}
