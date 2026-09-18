//! Host-only [`DurableDb`] backend over an in-memory SQLite database, so the
//! scheduler's SQL (queue schema, eligibility predicates, lease arithmetic)
//! is exercised by unit tests instead of only the pure `plan_alarm` policy.

use skyzen_services::durable::{
    DbExecResult, DbValue, DurableDb, DurableDbBackend, DurableDbError,
};
use sqlx::{Column as _, Row as _, TypeInfo as _, ValueRef as _, sqlite::SqliteRow};

use crate::errors::QueueError;
use crate::scheduler::queue::ensure_schema;

/// `DurableDbBackend` backed by a `sqlx` SQLite pool.
#[derive(Debug, Clone)]
struct SqliteBackend {
    pool: sqlx::SqlitePool,
}

/// Open a fresh in-memory queue database with the scheduler schema applied.
///
/// `max_connections(1)` is required: `sqlite::memory:` databases are scoped to
/// a single connection, so a wider pool would hand out independent empty
/// databases.
///
/// # Errors
///
/// Returns `QueueError::Sql` if the pool cannot be opened or `ensure_schema`
/// fails.
pub async fn memory_db() -> Result<DurableDb, QueueError> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .map_err(|error| QueueError::Sql(format!("open in-memory sqlite: {error}")))?;
    let db = DurableDb::new(SqliteBackend { pool });
    ensure_schema(&db).await?;
    Ok(db)
}

impl DurableDbBackend for SqliteBackend {
    async fn query(&self, query: &str, params: &[DbValue]) -> Result<DbExecResult, DurableDbError> {
        let rows = bind_params(sqlx::query(query), params)
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
        let result = bind_params(sqlx::query(query), params)
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
    let value: i64 = sqlx::query_scalar(sql)
        .fetch_one(pool)
        .await
        .map_err(backend_error)?;
    u64::try_from(value).map_err(backend_error)
}

fn bind_params<'q>(
    query: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    params: &[DbValue],
) -> sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
    let mut query = query;
    for param in params {
        query = match param {
            DbValue::Null => query.bind(Option::<String>::None),
            DbValue::Boolean(value) => query.bind(*value),
            DbValue::Integer(value) => query.bind(*value),
            DbValue::Real(value) => query.bind(*value),
            DbValue::Text(value) => query.bind(value.clone()),
            DbValue::Blob(value) => query.bind(value.clone()),
            // SQLite binds the richer DbValue variants as their portable
            // renderings, mirroring the sqlx backend's documented behavior.
            DbValue::Timestamp(value) => query.bind(value.to_rfc3339()),
            DbValue::Uuid(value) => query.bind(value.into_bytes().to_vec()),
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
/// and SQLite stores whatever class the expression produced.
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
