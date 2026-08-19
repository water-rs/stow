//! Centralized typed error model for the edge worker.
//!
//! Every internal helper returns one of the per-module error enums below
//! (`DbError`, `ResolverError`, `QueueError`, `SchedulerClientError`,
//! `MissLoggerError`). The handler-facing `GetArtifactError` (defined in
//! `api.rs`) absorbs them via `#[from]` so endpoints surface a single
//! `Internal` variant whose source is fully typed.
//!
//! Stringly-typed `Result<_, String>` paths in this crate are being phased
//! out in favor of these enums.

use stow_types::identity::IdentityError;

/// Errors raised by the D1 / artifact-catalog layer (`edge::db`).
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// A D1 query or migration failed.
    #[error("d1 query failed: {0}")]
    Query(String),
    /// A row read from D1 had a column with an invalid identity shape.
    #[error("invalid stored identity: {0}")]
    Identity(#[from] IdentityError),
    /// A semver string from a stored row could not be parsed.
    #[error("parse stored semver `{raw}`: {source}")]
    Semver {
        /// The raw value that failed to parse.
        raw: String,
        /// The underlying semver error.
        #[source]
        source: semver::Error,
    },
    /// Stored data violates an invariant (e.g. unsorted entries).
    #[error("stored data invariant violated: {0}")]
    Invariant(String),
}

impl From<String> for DbError {
    fn from(message: String) -> Self {
        Self::Query(message)
    }
}

impl From<String> for ResolverError {
    fn from(message: String) -> Self {
        Self::Json(message)
    }
}

impl From<String> for QueueError {
    fn from(message: String) -> Self {
        Self::Sql(message)
    }
}

impl From<ResolverError> for DbError {
    fn from(error: ResolverError) -> Self {
        match error {
            ResolverError::Db(inner) => inner,
            other => Self::Query(other.to_string()),
        }
    }
}

/// Errors raised by the dependency-resolver / graph expansion layer.
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    /// Wraps a D1 query made from the resolver path.
    #[error("db: {0}")]
    Db(#[from] DbError),
    /// HTTP fetch to crates.io failed.
    #[error("crates.io fetch: {0}")]
    CratesIo(String),
    /// JSON decode failed (crates.io response, cached row, etc.).
    #[error("decode JSON: {0}")]
    Json(String),
    /// An identity newtype rejected a value at construction.
    #[error("identity: {0}")]
    Identity(#[from] IdentityError),
    /// Generic invariant violation found while normalizing the graph.
    #[error("graph invariant: {0}")]
    Invariant(String),
}

/// Errors raised by the scheduler queue (Durable Object).
#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    /// Underlying durable-object SQL access failed.
    #[error("queue sql: {0}")]
    Sql(String),
    /// A completion report referenced a task the queue has no row for.
    #[error("completion report for unknown task `{0}`")]
    UnknownTask(String),
    /// Numeric overflow when packing a queue field.
    #[error("queue numeric overflow on `{field}`: {value}")]
    Overflow {
        /// Field name.
        field: &'static str,
        /// Offending value.
        value: u64,
    },
}

/// Errors raised when the edge talks to the scheduler Durable Object.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerClientError {
    /// Could not resolve the Durable Object stub.
    #[error("scheduler stub: {0}")]
    Stub(String),
    /// `worker::Request` construction failed.
    #[error("build scheduler request: {0}")]
    BuildRequest(String),
    /// `stub.fetch` returned an error.
    #[error("scheduler fetch {url}: {message}")]
    Fetch {
        /// URL that was being fetched.
        url: String,
        /// Underlying error message.
        message: String,
    },
    /// HTTP non-2xx response.
    #[error("scheduler {url} returned HTTP {status}: {body}")]
    Http {
        /// URL that was being fetched.
        url: String,
        /// HTTP status code.
        status: u16,
        /// Body for diagnostics.
        body: String,
    },
    /// JSON decode failed.
    #[error("decode scheduler response: {0}")]
    Decode(String),
}

/// Errors raised by the cache-miss logger.
#[derive(Debug, thiserror::Error)]
pub enum MissLoggerError {
    /// Wraps a D1 query made from the miss-logger path.
    #[error("db: {0}")]
    Db(#[from] DbError),
}
