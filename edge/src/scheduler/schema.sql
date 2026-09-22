CREATE TABLE IF NOT EXISTS queue (
    task_id TEXT PRIMARY KEY,
    crate_name TEXT NOT NULL,
    version TEXT NOT NULL,
    features_json TEXT NOT NULL,
    target TEXT NOT NULL,
    rustc_version TEXT NOT NULL,
    downloads INTEGER NOT NULL DEFAULT 0,
    miss_count INTEGER NOT NULL DEFAULT 0,
    request_count INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    error_msg TEXT,
    preserve_lockfile INTEGER NOT NULL DEFAULT 0,
    lane TEXT NOT NULL DEFAULT 'miss' CHECK (lane IN ('miss', 'human')),
    dispatch_attempts INTEGER NOT NULL DEFAULT 0,
    -- Enqueue epoch: bumped every time a re-request resurrects a
    -- failed/completed row, so a completion report only lands on the
    -- attempt that was dispatched for it.
    attempt INTEGER NOT NULL DEFAULT 1,
    not_before TEXT NOT NULL DEFAULT '1970-01-01 00:00:00',
    first_requested_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    -- GitHub Actions run id the dispatched build reported back through its
    -- OIDC-claimed register/complete calls; NULL until a run checks in.
    github_run_id TEXT,
    UNIQUE(crate_name, version, features_json, target, rustc_version)
);

-- Status and lane are the queue's hot predicates: status() groups by them,
-- claim and recover filter on them.
CREATE INDEX IF NOT EXISTS idx_queue_status_lane
ON queue (status, lane);

CREATE TABLE IF NOT EXISTS queue_dependencies (
    task_id TEXT NOT NULL,
    depends_on_task_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (task_id, depends_on_task_id)
);

-- Human-lane daily spend: one row per UTC date counting tasks enqueued
-- through the Turnstile-admitted lane. Charged by a conditional upsert in
-- `enqueue`, so a submit that would push the day over
-- STOW_HUMAN_DAILY_TASK_BUDGET is refused atomically instead of racing.
CREATE TABLE IF NOT EXISTS human_daily_task_budget (
    day TEXT PRIMARY KEY,
    task_count INTEGER NOT NULL
);

-- GitHub App installation token cache: a single row (id = 1) holding the
-- token the scheduler minted for workflow_dispatch plus GitHub's
-- expires_at, so a Durable Object restart reuses it instead of minting
-- again.
CREATE TABLE IF NOT EXISTS github_app_token (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    token TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- Operator-flipped settings. Currently holds only `panic`, the
-- anonymous-traffic circuit breaker: 'true'/'false', absent means off.
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Stable rustc channel cache: a single row (id = 1) holding the version
-- parsed out of channel-rust-stable.toml. The request API resolves the
-- current stable rustc through this table so repeated human requests do
-- not re-fetch the Rust release manifest; entries older than the TTL are
-- refreshed on the next request.
CREATE TABLE IF NOT EXISTS rust_stable_channel (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version TEXT NOT NULL,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
);
