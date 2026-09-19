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

impl From<IdentityError> for QueueError {
    fn from(error: IdentityError) -> Self {
        Self::Invariant(format!("stored identity rejected: {error}"))
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
    /// crates.io answered 404 — the crate (or version) is not published.
    /// Handlers map this to `404 Not Found`, not an internal error.
    #[error("crate `{crate_name}` is not published on crates.io")]
    CrateNotPublished {
        /// The crate name crates.io did not find.
        crate_name: String,
    },
    /// The crate is published but the exact version asked for is not in
    /// the registry index. Distinct from [`Self::CrateNotPublished`] so a
    /// bad version does not report the crate as missing.
    #[error("`{crate_name}` has no published version {version}")]
    VersionNotPublished {
        /// The crate the caller asked for.
        crate_name: String,
        /// The version that is not in the index.
        version: String,
    },
    /// JSON decode failed (crates.io response, cached row, etc.).
    #[error("decode JSON: {0}")]
    Json(String),
    /// An identity newtype rejected a value at construction.
    #[error("identity: {0}")]
    Identity(#[from] IdentityError),
    /// Generic invariant violation found while normalizing the graph.
    #[error("graph invariant: {0}")]
    Invariant(String),
    /// The caller's own input is malformed, rejected before any lookup ran.
    /// Handlers map this to `400 Bad Request` with the message verbatim,
    /// so it must stay free of upstream diagnostics.
    #[error("{0}")]
    BadRequest(String),
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
    /// Stored queue state contradicts an invariant (e.g. dispatch capacity
    /// reported exhausted while no dispatched/running row exists).
    #[error("queue invariant violated: {0}")]
    Invariant(String),
    /// Numeric overflow when packing a queue field.
    #[error("queue numeric overflow on `{field}`: {value}")]
    Overflow {
        /// Field name.
        field: &'static str,
        /// Offending value.
        value: u64,
    },
}

/// Errors raised by Cloudflare Turnstile siteverify.
#[derive(Debug, thiserror::Error)]
pub enum TurnstileError {
    /// Building or sending the siteverify POST failed.
    #[error("turnstile siteverify request: {0}")]
    Request(String),
    /// siteverify answered with a non-2xx status.
    #[error("turnstile siteverify returned HTTP {status}: {body}")]
    Http {
        /// HTTP status code.
        status: u16,
        /// Response body.
        body: String,
    },
    /// The siteverify JSON body could not be decoded.
    #[error("decode siteverify response: {0}")]
    Decode(String),
}

/// Errors raised while resolving the current stable rustc version.
#[derive(Debug, thiserror::Error)]
pub enum RustChannelError {
    /// The stable channel manifest fetch failed.
    #[error("rust channel fetch: {0}")]
    Fetch(String),
    /// The channel manifest could not be parsed into a rustc version.
    #[error("parse rust channel manifest: {0}")]
    Parse(String),
    /// Durable Object cache access failed.
    #[error("rust channel cache: {0}")]
    Cache(#[from] QueueError),
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
