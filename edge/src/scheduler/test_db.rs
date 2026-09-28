//! Host-only [`DurableDb`] backend over an in-memory `SQLite` database, so the
//! scheduler's SQL (queue schema, eligibility predicates, lease arithmetic)
//! is exercised by unit tests instead of only the pure `plan_alarm` policy.
//!
//! `rusqlite` is the driver rather than `sqlx`: `sqlx`'s sqlite crate pins a
//! `libsqlite3-sys` range that can no longer share one `links` owner with the
//! `cargo` crate's `rusqlite`, so the test database is built on the `rusqlite`
//! side instead of carrying a second `sqlite3` linkage.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rusqlite::types::Value;
use skyzen_services::durable::{
    DbExecResult, DbValue, DurableDb, DurableDbBackend, DurableDbError,
};
use skyzen_services::{BatchStatement, Db, DbBackend, DbDialect, DbError};

use crate::errors::QueueError;
use crate::scheduler::queue;

/// `DurableDbBackend` backed by a single `rusqlite` connection — `Clone`
/// hands every holder the same in-memory database, matching the
/// one-connection pool this replaces.
#[derive(Debug, Clone)]
pub struct SqliteBackend {
    conn: Arc<Mutex<rusqlite::Connection>>,
    /// Whether DDL and PRAGMA statements pass [`check_do_statements`].
    /// Migrations are operations work — only the migrate path may issue
    /// them — so the flag is on while a migration-capable database is
    /// constructed or handed to a migration test (`memory_db_raw`), and
    /// off on every database the request paths see. A statement that
    /// creates, alters, drops or probes the schema from request code
    /// fails the test instead of slipping to production, where the DO
    /// would accept the DDL but the ops rule forbids it.
    ddl_permitted: Arc<AtomicBool>,
}

impl SqliteBackend {
    fn open() -> Result<Self, rusqlite::Error> {
        let conn = rusqlite::Connection::open_in_memory()?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            ddl_permitted: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Revert the backend to request-path mode — every constructor that
    /// runs the migration calls this once it has applied the schema.
    fn close_migration(&self) {
        self.ddl_permitted.store(false, Ordering::Relaxed);
    }

    fn run_query(&self, query: &str, params: &[DbValue]) -> Result<DbExecResult, String> {
        check_do_statements(query, self.ddl_permitted.load(Ordering::Relaxed))
            .map_err(|e| e.to_string())?;
        let rows = {
            let conn = self.conn.lock().expect("sqlite connection");
            let mut statement = conn.prepare(query).map_err(|e| e.to_string())?;
            let columns = statement
                .column_names()
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let rows = statement
                .query(rusqlite::params_from_iter(db_values(params)))
                .map_err(|e| e.to_string())?
                .mapped(|row| row_to_json(row, &columns))
                .collect::<Result<Vec<_>, rusqlite::Error>>()
                .map_err(|e| e.to_string())?;
            drop(statement);
            drop(conn);
            rows
        };
        Ok(DbExecResult {
            rows_read: u64::try_from(rows.len()).unwrap_or(u64::MAX),
            rows,
            rows_written: 0,
        })
    }

    fn run_execute(&self, query: &str, params: &[DbValue]) -> Result<DbExecResult, String> {
        check_do_statements(query, self.ddl_permitted.load(Ordering::Relaxed))
            .map_err(|e| e.to_string())?;
        let rows_written = {
            let conn = self.conn.lock().expect("sqlite connection");
            if params.is_empty() {
                // Unbound statements are DDL or multi-statement SQL
                // (schema.sql); rusqlite's `execute` stops after the first
                // statement, `execute_batch` runs them all.
                conn.execute_batch(query).map_err(|e| e.to_string())?;
                0
            } else {
                conn.execute(query, rusqlite::params_from_iter(db_values(params)))
                    .map_err(|e| e.to_string())?
            }
        };
        Ok(DbExecResult {
            rows: Vec::new(),
            rows_read: 0,
            rows_written: u64::try_from(rows_written).unwrap_or(u64::MAX),
        })
    }
}

/// Open a fresh in-memory queue database with the scheduler schema applied.
///
/// # Errors
///
/// Returns `QueueError::Sql` if the database cannot be opened or `migrate`
/// fails.
pub async fn memory_db() -> Result<DurableDb, QueueError> {
    let backend = memory_backend()?;
    let db = DurableDb::new(backend.clone());
    queue::migrate(&db).await?;
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
/// Returns `QueueError::Sql` if the database cannot be opened.
pub async fn memory_db_raw() -> Result<DurableDb, QueueError> {
    Ok(DurableDb::new(memory_backend()?))
}

/// A fresh in-memory `sqlite` [`Db`] for the artifact-catalog tests in
/// `crate::db`, replacing `Db::connect_sqlite_memory` which lives behind the
/// `sqlite` feature this crate no longer enables.
///
/// # Errors
///
/// Returns `DbError::Backend` if the database cannot be opened.
pub fn sql_memory_db() -> Result<Db, DbError> {
    Ok(Db::new(SqliteBackend::open().map_err(|error| {
        DbError::Backend {
            message: format!("open in-memory sqlite: {error}"),
            source: None,
        }
    })?))
}

/// Every statement the wrapped backend ran, in order — `(sql, elapsed)`.
/// The submit-path measurements for issue #418 read this after a run to
/// report statement counts per request and per dependency edge.
pub type StatementLog =
    std::sync::Arc<std::sync::Mutex<Vec<(std::string::String, std::time::Duration)>>>;

/// Open a fresh in-memory queue database (schema applied) whose backend
/// records every statement it executes, returning the log alongside.
///
/// # Errors
///
/// Returns `QueueError::Sql` if the database cannot be opened or `migrate`
/// fails.
pub async fn counting_memory_db() -> Result<(DurableDb, StatementLog), QueueError> {
    let log = StatementLog::default();
    let inner = memory_backend()?;
    let db = DurableDb::new(CountingBackend {
        inner: inner.clone(),
        log: log.clone(),
    });
    queue::migrate(&db).await?;
    inner.close_migration();
    Ok((db, log))
}

fn memory_backend() -> Result<SqliteBackend, QueueError> {
    SqliteBackend::open()
        .map_err(|error| QueueError::Sql(format!("open in-memory sqlite: {error}")))
}

/// A `SqliteBackend` wrapper that appends every statement and its wall
/// time to a shared log before returning the real result.
#[derive(Debug, Clone)]
struct CountingBackend {
    inner: SqliteBackend,
    log: StatementLog,
}

impl CountingBackend {
    fn record(&self, sql: &str, elapsed: std::time::Duration) {
        self.log
            .lock()
            .expect("statement log")
            .push((sql.to_owned(), elapsed));
    }
}

impl DurableDbBackend for CountingBackend {
    async fn query(&self, query: &str, params: &[DbValue]) -> Result<DbExecResult, DurableDbError> {
        let start = std::time::Instant::now();
        let result = DurableDbBackend::query(&self.inner, query, params).await;
        self.record(query, start.elapsed());
        result
    }

    async fn execute(
        &self,
        query: &str,
        params: &[DbValue],
    ) -> Result<DbExecResult, DurableDbError> {
        let start = std::time::Instant::now();
        let result = DurableDbBackend::execute(&self.inner, query, params).await;
        self.record(query, start.elapsed());
        result
    }

    fn database_size(&self) -> impl Future<Output = Result<u64, DurableDbError>> + Send {
        self.inner.database_size()
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
    fn query(
        &self,
        query: &str,
        params: &[DbValue],
    ) -> impl Future<Output = Result<DbExecResult, DurableDbError>> + Send {
        std::future::ready(self.run_query(query, params).map_err(durable_error))
    }

    fn execute(
        &self,
        query: &str,
        params: &[DbValue],
    ) -> impl Future<Output = Result<DbExecResult, DurableDbError>> + Send {
        std::future::ready(self.run_execute(query, params).map_err(durable_error))
    }

    fn database_size(&self) -> impl Future<Output = Result<u64, DurableDbError>> + Send {
        std::future::ready(
            pragma_i64(self, "PRAGMA page_count")
                .and_then(|page_count| {
                    pragma_i64(self, "PRAGMA page_size")
                        .map(|page_size| page_count.checked_mul(page_size))
                })
                .and_then(|size| size.ok_or(rusqlite::Error::IntegralValueOutOfRange(0, -1)))
                .map_err(durable_error),
        )
    }
}

impl DbBackend for SqliteBackend {
    fn dialect(&self) -> DbDialect {
        DbDialect::Sqlite
    }

    fn query(
        &self,
        query: &str,
        params: &[DbValue],
    ) -> impl Future<Output = Result<DbExecResult, DbError>> + Send {
        std::future::ready(self.run_query(query, params).map_err(sql_error))
    }

    fn execute(
        &self,
        query: &str,
        params: &[DbValue],
    ) -> impl Future<Output = Result<DbExecResult, DbError>> + Send {
        std::future::ready(self.run_execute(query, params).map_err(sql_error))
    }

    fn execute_batch(
        &self,
        statements: Vec<BatchStatement>,
    ) -> impl Future<Output = Result<Vec<DbExecResult>, DbError>> + Send {
        std::future::ready(self.run_batch(&statements))
    }
}

impl SqliteBackend {
    /// `Db::execute_batch` promises all-or-nothing: wrap the run in a
    /// transaction and roll back on the first failure.
    fn run_batch(&self, statements: &[BatchStatement]) -> Result<Vec<DbExecResult>, DbError> {
        let conn = self.conn.lock().expect("sqlite connection");
        conn.execute_batch("BEGIN IMMEDIATE").map_err(sql_error)?;
        let mut results = Vec::with_capacity(statements.len());
        let outcome = statements.iter().try_for_each(|statement| {
            conn.prepare(&statement.sql)
                .and_then(|mut prepared| {
                    prepared.execute(rusqlite::params_from_iter(db_values(&statement.params)))
                })
                .map(|rows_written| {
                    results.push(DbExecResult {
                        rows: Vec::new(),
                        rows_read: 0,
                        rows_written: u64::try_from(rows_written).unwrap_or(u64::MAX),
                    });
                })
                .map_err(sql_error)
        });
        let result = match outcome {
            Ok(()) => conn
                .execute_batch("COMMIT")
                .map(|()| results)
                .map_err(sql_error),
            Err(error) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(error)
            }
        };
        drop(conn);
        result
    }
}

fn backend_error(error: impl std::fmt::Display) -> DurableDbError {
    DurableDbError::Backend {
        message: error.to_string(),
        source: None,
    }
}

fn durable_error(error: impl std::fmt::Display) -> DurableDbError {
    backend_error(error)
}

fn sql_error(error: impl std::fmt::Display) -> DbError {
    DbError::Backend {
        message: error.to_string(),
        source: None,
    }
}

fn pragma_i64(backend: &SqliteBackend, sql: &str) -> Result<u64, rusqlite::Error> {
    let conn = backend.conn.lock().expect("sqlite connection");
    let value: i64 = conn.query_row(sql, [], |row| row.get(0))?;
    drop(conn);
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

/// Bind as rusqlite's `types::Value`; the richer `DbValue` variants bind as
/// the text renderings the Durable Object SQL backend this harness stands in
/// for uses, so a test writes the same bytes production would.
fn db_values(params: &[DbValue]) -> Vec<Value> {
    params
        .iter()
        .map(|param| match param {
            DbValue::Null => Value::Null,
            DbValue::Boolean(value) => Value::Integer(i64::from(*value)),
            DbValue::Integer(value) => Value::Integer(*value),
            DbValue::Real(value) => Value::Real(*value),
            DbValue::Text(value) => Value::Text(value.clone()),
            DbValue::Blob(value) => Value::Blob(value.clone()),
            DbValue::Timestamp(value) => Value::Text(value.to_rfc3339()),
            DbValue::Uuid(value) => Value::Text(value.to_string()),
            DbValue::Decimal(value) => Value::Text(value.to_string()),
            DbValue::Json(value) => Value::Text(value.to_string()),
        })
        .collect()
}

fn row_to_json(
    row: &rusqlite::Row<'_>,
    columns: &[String],
) -> Result<serde_json::Value, rusqlite::Error> {
    let mut object = serde_json::Map::with_capacity(columns.len());
    for (index, column) in columns.iter().enumerate() {
        object.insert(column.clone(), value_to_json(row, index)?);
    }
    Ok(serde_json::Value::Object(object))
}

/// Convert by the value's runtime storage class, not the column's declared
/// type: expression columns (`count(*)`, `CAST`, `datetime()`) declare none,
/// and `SQLite` stores whatever class the expression produced.
fn value_to_json(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> Result<serde_json::Value, rusqlite::Error> {
    use rusqlite::types::ValueRef;
    Ok(match row.get_ref(index)? {
        ValueRef::Null => serde_json::Value::Null,
        ValueRef::Integer(value) => serde_json::json!(value),
        ValueRef::Real(value) => serde_json::json!(value),
        ValueRef::Text(value) => {
            serde_json::json!(std::str::from_utf8(value).unwrap_or_default())
        }
        ValueRef::Blob(value) => serde_json::json!(value),
    })
}
