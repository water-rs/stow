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
    -- The unit's compile side: 1 for a host-side node (a proc-macro,
    -- build dependency or build-script unit — minted on the runner
    -- family's host triple and built the way consumers compile it as a
    -- host unit), 0 for a target-side node. Part of the identity: the
    -- same crate legitimately exists at both sides of one triple.
    host_side INTEGER NOT NULL DEFAULT 0,
    -- Repair latch: 1 once a `completed` row has been re-queued because a
    -- dependent's edge required unit shapes its published rows never
    -- covered (shapeless legacy rows satisfy no gate clause). The
    -- re-queue is at most once — the rebuild republishes real shapes, so
    -- the missing-shape condition cannot recur.
    shape_requeue INTEGER NOT NULL DEFAULT 0,
    UNIQUE(crate_name, version, features_json, target, rustc_version, host_side)
);

-- Status and lane are the queue's hot predicates: status() groups by them,
-- claim and recover filter on them.
CREATE INDEX IF NOT EXISTS idx_queue_status_lane
ON queue (status, lane);

-- Dependency edges between queue tasks. The dep_* columns hold the
-- dependency's semantic identity verbatim so DEPENDENCY_NOT_BLOCKED_SQL
-- can join published_slice_rows without the dependency's own queue row —
-- depends_on_task_id is a one-way hash of it, and rows are rewritten
-- wholesale whenever an enqueue for the same identity arrives (see
-- sync_task_dependencies).
CREATE TABLE IF NOT EXISTS queue_dependencies (
    task_id TEXT NOT NULL,
    depends_on_task_id TEXT NOT NULL,
    dep_crate_name TEXT NOT NULL DEFAULT '',
    dep_version TEXT NOT NULL DEFAULT '',
    dep_features_json TEXT NOT NULL DEFAULT '',
    dep_target TEXT NOT NULL DEFAULT '',
    dep_rustc_version TEXT NOT NULL DEFAULT '',
    -- Whether the dependent needs this dep as a host-side unit. Edges
    -- written before the column existed default 0 — the target-side
    -- shape requirement the gate always applied.
    dep_host_side INTEGER NOT NULL DEFAULT 0,
    -- The gate's required shapes, precomputed at edge-write time (see
    -- dep_invocation_mask / dep_edge_unpublished_sql in queue.rs):
    -- dep_invocations is the bitmask of cargo invocation spellings the
    -- dependent's build compiles the dep under (1 = native, 2 =
    -- --target, 3 = both for a host-side dependent), and dep_shapes is
    -- the distinct (invocation, linked) pairs the slice must publish
    -- before the dependent may dispatch. 0 marks an edge written before
    -- the columns existed; it fails closed until resynced.
    dep_invocations INTEGER NOT NULL DEFAULT 0,
    dep_shapes INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (task_id, depends_on_task_id)
);

-- What each published index slice serves, reported by the index-publish
-- path itself after a slice goes live. A report writes its rows under a
-- fresh generation, then flips published_slices.generation in one
-- statement — the commit point — so the gate either sees the previous
-- report in full or the new one in full, never a half-written slice.
-- Rows of superseded generations are deleted after the flip (see
-- record_published_slice in queue.rs). The dependency gate
-- (DEPENDENCY_NOT_BLOCKED_SQL) releases a dependent only when every edge
-- resolves to a row of the live generation for the dependency's own
-- slice.
CREATE TABLE IF NOT EXISTS published_slices (
    target TEXT NOT NULL,
    rustc_version TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 0,
    published_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (target, rustc_version)
);

CREATE TABLE IF NOT EXISTS published_slice_rows (
    target TEXT NOT NULL,
    rustc_version TEXT NOT NULL,
    generation INTEGER NOT NULL,
    crate_name TEXT NOT NULL,
    version TEXT NOT NULL,
    features_json TEXT NOT NULL,
    -- The unit shape the row serves — the builder-recorded side, cargo
    -- invocation spelling, and link kind the dependency gate compares an
    -- edge's required shapes against. -1 on all three legs marks a row
    -- reported before the columns existed: shapeless rows satisfy no
    -- coverage clause and the dependent stays gated until the node
    -- rebuilds and republishes.
    unit_side INTEGER NOT NULL DEFAULT -1,
    unit_invocation INTEGER NOT NULL DEFAULT -1,
    unit_linked INTEGER NOT NULL DEFAULT -1,
    PRIMARY KEY (target, rustc_version, generation, crate_name, version, features_json, unit_side, unit_invocation, unit_linked)
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
