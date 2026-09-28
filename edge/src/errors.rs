//! Centralized typed error model for the edge worker.
//!
//! Every internal helper returns one of the per-module error enums below
//! (`DbError`, `ResolverError`, `QueueError`, `SchedulerClientError`). The
//! handler-facing `GetArtifactError` absorbs them via `From` impls so
//! endpoints answer a single error type whose status mapping is
//! host-testable.
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
    /// An upstream fetch failed — crates.io, github.com, or the
    /// rustc-data base. Handlers map this to 5xx; retrying may help.
    #[error("upstream fetch: {0}")]
    Upstream(String),
    /// The source repository or ref a projects-lane request named does
    /// not exist — the anonymous GitHub tree fetch answered 404.
    /// Handlers map this to `404 Not Found` naming `repo`@`git_ref`.
    #[error("`{repo}` at `{git_ref}` was not found on github.com")]
    RepoNotFound {
        /// The `owner/repo` the request asked for.
        repo: String,
        /// The ref the request asked for.
        git_ref: String,
    },
    /// The project's own manifest or dependency graph cannot be resolved
    /// — cargo's answer for this workspace, not an edge or upstream
    /// fault. Handlers map this to `422 Unprocessable Entity` carrying
    /// the full resolver error chain; the same request resolves the same
    /// way, so retrying cannot help.
    #[error("{0}")]
    Unresolvable(String),
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
    /// The request exceeded a documented edge limit. Handlers map this to
    /// a client-visible `413 Payload Too Large` naming the limit — not an
    /// internal error — because retrying the same request can never help.
    #[error(
        "{what} exceeds the edge limit of {limit} (got {got}); split the request into smaller batches"
    )]
    LimitExceeded {
        /// What was counted (e.g. `dependency graph entries`).
        what: &'static str,
        /// The observed count.
        got: usize,
        /// The configured maximum.
        limit: usize,
    },
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
    /// A completion report named a real task but not its live attempt or
    /// an in-flight status — a stale report for a superseded attempt or a
    /// duplicate of one already applied. Handlers map this to `409
    /// Conflict`: the report applied to nothing and retrying it unchanged
    /// can never succeed.
    #[error(
        "completion report for task `{task_id}` attempt {attempt} conflicts with the row's live state (attempt {row_attempt}, status `{row_status}`)"
    )]
    StaleCompletion {
        /// The task id the report named.
        task_id: String,
        /// The attempt the report claimed.
        attempt: u32,
        /// The attempt the queue row is currently on.
        row_attempt: u32,
        /// The row's current status.
        row_status: String,
    },
    /// The `STOW_MAX_QUEUE_PENDING` gate refused a miss-lane submit: the
    /// queue already holds `cap` pending tasks.
    #[error("scheduler queue is full: {pending} pending tasks >= cap {cap}")]
    QueueFull {
        /// Pending tasks when the submit was refused.
        pending: u32,
        /// Configured `STOW_MAX_QUEUE_PENDING`.
        cap: u32,
    },
    /// Today's `STOW_HUMAN_DAILY_TASK_BUDGET` cannot absorb the submit's
    /// human-lane tasks.
    #[error(
        "human-lane daily task budget exhausted: refusing {attempted} tasks (budget {budget} per UTC day)"
    )]
    HumanDailyBudgetExhausted {
        /// Human-lane tasks the refused submit carried.
        attempted: u64,
        /// Configured `STOW_HUMAN_DAILY_TASK_BUDGET`.
        budget: u64,
    },
    /// A queue mutation selector named no rows: empty `task_ids` and a
    /// filter with no predicates would touch every row in the queue.
    /// Handlers map this to `400 Bad Request`.
    #[error("queue mutation selector is empty: name task_ids or at least one filter predicate")]
    EmptySelector,
    /// A purge selector carried no `older_than_secs` age floor, so it
    /// could delete rows that finished moments ago.
    /// Handlers map this to `400 Bad Request`.
    #[error("queue purge requires filter.older_than_secs so live work cannot be swept")]
    PurgeRequiresAge,
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
    /// The Workers Cache API rejected the version read or write.
    /// `CacheError` exists only on wasm (the cache module binds CF
    /// types), so the variant does too.
    #[cfg(target_arch = "wasm32")]
    #[error("rust channel cache: {0}")]
    Cache(#[from] crate::cache::CacheError),
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

/// Unwrap the scheduler's `{"error": "..."}` JSON envelope so a refusal's
/// message reaches the client once, not nested inside a second object;
/// an unexpected body passes through verbatim.
pub fn scheduler_error_message(body: &str) -> &str {
    #[derive(serde::Deserialize)]
    struct ErrorBody<'a> {
        error: &'a str,
    }
    serde_json::from_str::<ErrorBody<'_>>(body).map_or(body, |parsed| parsed.error)
}

/// The error every serving endpoint answers. It lives here — in the
/// host-testable half of the crate — rather than with the handlers so
/// its status mapping runs under `cargo test` on the host target.
#[skyzen::error]
pub enum GetArtifactError {
    #[error("bad request", status = BAD_REQUEST)]
    BadRequest,
    /// A rejected request whose reason is safe to show the caller — the
    /// request page renders the body's `error` verbatim.
    #[error("{0}", status = BAD_REQUEST)]
    BadRequestWithMessage(String),
    #[error("unauthorized", status = UNAUTHORIZED)]
    Unauthorized,
    /// Turnstile rejected the request. The request-API contract renders
    /// this as `{"error":"turnstile rejected","error-codes":[...]}` — a
    /// shape the shared `{"error": ...}` renderer cannot express — so
    /// handlers return [`Self::rejection_response`] instead of `Err`.
    /// `status = FORBIDDEN` keeps even that fallback path correct.
    #[error("turnstile rejected", status = FORBIDDEN)]
    TurnstileRejected {
        /// Codes surfaced to the client verbatim (`siteverify-unavailable`,
        /// `hostname-mismatch`, or siteverify's own `error-codes`).
        error_codes: Vec<String>,
    },
    #[error("artifact not found", status = NOT_FOUND)]
    NotFound,
    /// The caller asked to build a target trusted CI has no runner for.
    /// Refused here so it can never become a dispatch: `build-crate.yml`
    /// resolves an unknown target to an empty `runs-on`, and the run then
    /// dies before any job starts, spending a queue slot and reporting
    /// nothing.
    #[error(
        "`{target}` is not a target this cache builds; supported: {supported}",
        status = BAD_REQUEST
    )]
    UnsupportedTarget {
        /// The target the caller asked for.
        target: String,
        /// The targets trusted CI can build, comma-separated.
        supported: String,
    },
    /// A request named a crate (or an exact version) crates.io does not
    /// publish; the message names it because the request page shows the
    /// body's `error` verbatim.
    #[error("crate `{crate_name}` is not published on crates.io", status = NOT_FOUND)]
    CrateNotPublished {
        /// The crate the caller asked for.
        crate_name: String,
    },
    /// The crate exists but the requested version does not (or every
    /// candidate is yanked or a prerelease).
    #[error("`{crate_name}` has no published {requested}", status = NOT_FOUND)]
    VersionNotPublished {
        /// The crate the caller asked for.
        crate_name: String,
        /// `version X.Y.Z` when one was asked for, else `stable release`.
        requested: String,
    },
    /// `GET /api/v1/requests/{task_id}` for a task the scheduler does not
    /// know: never enqueued, or already reaped.
    #[error("unknown request task id `{task_id}`", status = NOT_FOUND)]
    UnknownTask {
        /// The id from the request path.
        task_id: String,
    },
    /// The repository or ref a projects-lane request named does not
    /// exist — the anonymous GitHub tree fetch answered 404. The body
    /// names `repo`@`ref` so the caller can fix the request.
    #[error("`{repo}` at `{git_ref}` was not found on github.com", status = NOT_FOUND)]
    RepoNotFound {
        /// The `owner/repo` the request asked for.
        repo: String,
        /// The ref the request asked for.
        git_ref: String,
    },
    /// The scheduler refused a completion report because its attempt no
    /// longer matches the queue row's live state — a stale report for a
    /// superseded attempt or a duplicate. The body is the scheduler's own
    /// message, which already names the task and both attempts.
    #[error("{0}", status = CONFLICT)]
    CompletionConflict(String),
    /// A register request's record set escapes the authority of the task
    /// the caller named — a record whose target or rustc version differs
    /// from the task's, or a `(crate, version)` outside the task's
    /// dependency closure. The message names the offending record.
    #[error("{0}", status = FORBIDDEN)]
    RegisterForbidden(String),
    /// A register request named a task that cannot accept records —
    /// unknown to the scheduler queue, or not in an in-flight
    /// (`dispatched`/`running`) state. A conflict, not a credential
    /// failure: the caller authenticated, the named work is just not the
    /// live row it claims.
    #[error("{0}", status = CONFLICT)]
    RegisterConflict(String),
    #[error("GHCR unavailable", status = BAD_GATEWAY)]
    GhcrUnavailable,
    /// GitHub (OIDC JWKS or the repo-permission API) could not be consulted
    /// — a 502 so CI retries instead of recording a permanent auth failure.
    /// The upstream reason stays in the worker log.
    #[error("github trust upstream unavailable", status = BAD_GATEWAY)]
    TrustUpstreamUnavailable,
    /// GitHub rate-limited the trust check itself — a 503 so CI backs
    /// off rather than hammering the probe that triggered the limit.
    /// The `TrustRateLimitGate` middleware turns this into a 503 with the
    /// `Retry-After` GitHub asked for; this variant is the bare-status
    /// fallback when it surfaces through the shared error envelope.
    #[error("github trust upstream rate limited", status = SERVICE_UNAVAILABLE)]
    TrustUpstreamRateLimited,
    /// A request exceeded a documented edge limit. The message names the
    /// observed count and the limit — a client error (413 renders its
    /// message, 5xx does not), because retrying the same request can
    /// never help.
    #[error("{0}", status = PAYLOAD_TOO_LARGE)]
    TooLarge(String),
    /// The request is well-formed but the edge declines to process it —
    /// e.g. a `POST /api/v1/requests` dependency closure over
    /// `STOW_HUMAN_MAX_CLOSURE`. Retrying unchanged can never help.
    #[error("{0}", status = UNPROCESSABLE_ENTITY)]
    UnprocessableEntity(String),
    /// The scheduler refused a submit with 429 — on the human lane the
    /// daily task budget, on the miss lane the pending-depth cap.
    /// Handlers that know the retry semantics answer a `Retry-After`
    /// response instead; this status is the fallback for paths that
    /// surface the error as-is.
    #[error("{0}", status = TOO_MANY_REQUESTS)]
    SchedulerBusy(String),
    /// Dispatch is frozen (systematic-failure or cost trip). The body's
    /// `error` names the stored trigger so the operator sees why.
    #[error("{0}", status = SERVICE_UNAVAILABLE)]
    DispatchFrozen(String),
    #[error("internal server error: {0}")]
    InternalWithMessage(String),
}

impl From<SchedulerClientError> for GetArtifactError {
    fn from(error: SchedulerClientError) -> Self {
        match error {
            // A 429 is a capacity refusal — the queue-depth cap or the
            // human-lane daily budget — not a malformed request. The body
            // is the scheduler's own `{"error": ...}` JSON; unwrap it so
            // the message is not nested inside a second envelope.
            SchedulerClientError::Http {
                status: 429, body, ..
            } => Self::SchedulerBusy(scheduler_error_message(&body).to_owned()),
            // A 503 is the dispatch freeze's refusal — the trusted
            // submit and admin enqueue paths answer it verbatim so the
            // caller sees the freeze reason, not a bare 500.
            SchedulerClientError::Http {
                status: 503, body, ..
            } => Self::DispatchFrozen(scheduler_error_message(&body).to_owned()),
            // A 4xx from the scheduler is a client problem — e.g. a
            // completion report naming a task the queue never held — and
            // the body is the scheduler's own client-safe message, so it
            // reaches the reporter verbatim instead of as a bare 500.
            SchedulerClientError::Http { status, body, .. } if (400..500).contains(&status) => {
                Self::BadRequestWithMessage(format!("scheduler rejected the report: {body}"))
            }
            other => Self::InternalWithMessage(other.to_string()),
        }
    }
}

impl From<DbError> for GetArtifactError {
    fn from(error: DbError) -> Self {
        Self::InternalWithMessage(error.to_string())
    }
}

impl From<RustChannelError> for GetArtifactError {
    fn from(error: RustChannelError) -> Self {
        // Fetch and parse failures are upstream problems
        // (static.rust-lang.org, or the Cache API) — the caller cannot
        // fix them, so they surface as the 500 the detail string rides.
        Self::InternalWithMessage(error.to_string())
    }
}

impl From<ResolverError> for GetArtifactError {
    fn from(error: ResolverError) -> Self {
        match error {
            ResolverError::CrateNotPublished { crate_name } => {
                Self::CrateNotPublished { crate_name }
            }
            ResolverError::LimitExceeded { .. } => Self::TooLarge(error.to_string()),
            ResolverError::VersionNotPublished {
                crate_name,
                version,
            } => Self::VersionNotPublished {
                crate_name,
                requested: format!("version {version}"),
            },
            ResolverError::RepoNotFound { repo, git_ref } => Self::RepoNotFound { repo, git_ref },
            ResolverError::Unresolvable(message) => Self::UnprocessableEntity(message),
            ResolverError::BadRequest(message) => Self::BadRequestWithMessage(message),
            other => Self::InternalWithMessage(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GetArtifactError, ResolverError};
    use skyzen::{HttpError as _, StatusCode};

    /// A missing source repository answers 404 with `repo`@`ref` in the
    /// body — the caller can fix the request — not a redacted 500.
    #[test]
    fn repo_not_found_maps_to_404_naming_the_repo_and_ref() {
        let error = GetArtifactError::from(ResolverError::RepoNotFound {
            repo: "owner/missing".to_owned(),
            git_ref: "dev".to_owned(),
        });
        assert_eq!(error.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            error.to_string(),
            "`owner/missing` at `dev` was not found on github.com"
        );
    }

    /// The project's own dependency graph failing to resolve answers 422
    /// carrying cargo's error chain — the body tells the caller their
    /// manifest is the problem, not the edge.
    #[test]
    fn unresolvable_maps_to_422_with_the_resolver_message() {
        let error = GetArtifactError::from(ResolverError::Unresolvable(
            "resolve failed: failed to select a version for `dep`".to_owned(),
        ));
        assert_eq!(error.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            error.to_string(),
            "resolve failed: failed to select a version for `dep`"
        );
    }

    /// An upstream fetch failure stays a server error — its detail is
    /// redacted from the body by the shared renderer, so only the status
    /// is asserted here.
    #[test]
    fn upstream_maps_to_500() {
        let error = GetArtifactError::from(ResolverError::Upstream(
            "fetch crates.io: refused".to_owned(),
        ));
        assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
