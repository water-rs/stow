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
    -- GitHub Actions run id recorded when the build's workflow_run
    -- webhook completed the task; NULL until the webhook lands.
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
    -- The dependency gate's answer, persisted: 1 while every edge of this
    -- row resolves to units the published slice serves. Written at edge
    -- sync, recomputed by every transition into `pending`, and refreshed
    -- on pending rows only where an edge or slice write can change the
    -- answer — the claim reads the flag only on pending rows, so a
    -- dispatch pass never re-evaluates the dependency EXISTS.
    deps_met INTEGER NOT NULL DEFAULT 0,
    -- The dependency gate's terminal answer, persisted: 1 while a
    -- pending row owns an edge whose dep failed or was never resolved
    -- and whose required units the published slice does not serve —
    -- the set `effective_status` used to recompute per row on every
    -- read. Maintained wherever `deps_met` is, plus on the dependents
    -- of a task whose status flips into or out of `failed` — those are
    -- the only transitions that move the flag. Only meaningful on
    -- pending rows; a stale value on another status is never observed.
    blocked INTEGER NOT NULL DEFAULT 0,
    -- The earliest instant the row is dispatchable: the later of
    -- `first_requested_at + dispatch_min_age` and the `not_before`
    -- backoff gate, rendered as the row is written (the human lane
    -- pays no minimum age, so its wake is just `not_before`). Read by
    -- the alarm's wake probes — the claim re-checks eligibility from
    -- the live columns, so a stale value costs at most a cheap
    -- pass, never a wrong dispatch.
    wake_at TEXT NOT NULL DEFAULT '1970-01-01 00:00:00',
    -- The row's runner family ('linux'/'macos'/'windows'), set once at
    -- enqueue — target never changes. Lets the wake-time probes prefix
    -- equality-filter by family instead of scanning.
    dispatch_family TEXT NOT NULL DEFAULT '',
    -- The claim ORDER BY tuple encoded as one sortable string:
    -- lane rank | family rank (Windows first) | first_requested_at |
    -- inverted priority | created_at | task_id. The claim walk orders by
    -- it under an index and pages by keyset, so a dispatch pass reads
    -- rows proportional to the slots it fills, not the queue size.
    dispatch_key TEXT NOT NULL DEFAULT '',
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
    -- The side of the dep the dependent needs. -1 marks an edge written
    -- before the side model whose side the migration could not derive
    -- (a dep on the family host triple under an owner on the same
    -- triple is ambiguous): `p.unit_side = -1` matches no published
    -- row, so the gate holds the dependent until the resolver rewrites
    -- the edge with a real side.
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
    -- Whether the edge's required side is established — resolver-written
    -- edges carry 1, legacy rows the side migration derives stamp their
    -- outcome and mark themselves known so it runs once.
    dep_side_known INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (task_id, depends_on_task_id)
);

-- The claim walk: pending + deps-met rows in dispatch order. The alarm's
-- dispatch pass reads the first page of this index, never the queue.
-- `dispatch_key` is unique within a status group, so the trailing
-- residual-filter columns (`dispatch_family`, `lane`,
-- `first_requested_at`, `not_before`) do not disturb the ORDER BY — they
-- let a skipped index entry answer the family/lane/age checks without
-- fetching the row.
CREATE INDEX IF NOT EXISTS idx_queue_dispatch
ON queue (status, deps_met, dispatch_key, dispatch_family, lane, first_requested_at, not_before);

-- The alarm's wake probes: `SELECT 1 … wake_at <= now LIMIT 1` (already
-- dispatchable) and `MIN(wake_at) … wake_at > now` (earliest deferred
-- wake) — both bounded by the `wake_at` ordering, with
-- `dispatch_family` before it so a saturated family's deferred rows do
-- not stand ahead of another family's earliest wake in the same walk.
CREATE INDEX IF NOT EXISTS idx_queue_wake_eligible
ON queue (status, deps_met, dispatch_family, wake_at);

-- Admin's oldest-pending MIN and the 24h outcome window.
CREATE INDEX IF NOT EXISTS idx_queue_status_first
ON queue (status, first_requested_at);

CREATE INDEX IF NOT EXISTS idx_queue_status_updated
ON queue (status, updated_at);

-- `list_tasks`'s newest-first tail read: the ORDER BY walks this index
-- and stops at the page's LIMIT.
CREATE INDEX IF NOT EXISTS idx_queue_updated_at
ON queue (updated_at);

-- The pending/blocked selectors' page: pending rows ordered newest
-- first within each `blocked` arm, so a `?status=pending` or
-- `?status=blocked` listing stops at its LIMIT instead of walking the
-- pending set until enough unfiltered rows accumulate.
CREATE INDEX IF NOT EXISTS idx_queue_pending_live
ON queue (blocked, updated_at) WHERE status = 'pending';

-- `list_tasks` selector bounds: a `target` or `crate_name` filtered
-- listing walks the matching group of its own index under the same
-- newest-first ordering instead of scanning `idx_queue_updated_at` for
-- matches.
CREATE INDEX IF NOT EXISTS idx_queue_target_updated
ON queue (target, updated_at);

CREATE INDEX IF NOT EXISTS idx_queue_crate_updated
ON queue (crate_name, updated_at);

-- The exact (status, lane) counts `status()` reports, maintained by
-- trigger instead of a whole-queue GROUP BY on every request. The
-- triggers fire on every write path — request handlers, operator
-- mutations, fixtures and the migration's own row moves — so no code
-- path maintains the table by hand; `migrate` rebuilds it wholesale
-- once, in case it ever drifted.
CREATE TABLE IF NOT EXISTS queue_status_counts (
    status TEXT NOT NULL,
    lane TEXT NOT NULL,
    -- `blocked` is part of the key so `status()` reads the blocked
    -- count off the counter rows too — the (pending, *, 1) rows —
    -- instead of evaluating the fatal-edge EXISTS across the graph on
    -- every request.
    blocked INTEGER NOT NULL DEFAULT 0,
    n INTEGER NOT NULL,
    PRIMARY KEY (status, lane, blocked)
);

CREATE TRIGGER IF NOT EXISTS queue_counts_on_insert AFTER INSERT ON queue
BEGIN
    INSERT INTO queue_status_counts (status, lane, blocked, n)
        VALUES (NEW.status, NEW.lane, NEW.blocked, 1)
    ON CONFLICT (status, lane, blocked) DO UPDATE SET n = n + 1;
END;

CREATE TRIGGER IF NOT EXISTS queue_counts_on_delete AFTER DELETE ON queue
BEGIN
    INSERT INTO queue_status_counts (status, lane, blocked, n)
        VALUES (OLD.status, OLD.lane, OLD.blocked, -1)
    ON CONFLICT (status, lane, blocked) DO UPDATE SET n = n - 1;
END;

CREATE TRIGGER IF NOT EXISTS queue_counts_on_move
    AFTER UPDATE OF status, lane, blocked ON queue
    WHEN OLD.status != NEW.status OR OLD.lane != NEW.lane
       OR OLD.blocked != NEW.blocked
BEGIN
    INSERT INTO queue_status_counts (status, lane, blocked, n)
        VALUES (OLD.status, OLD.lane, OLD.blocked, -1)
    ON CONFLICT (status, lane, blocked) DO UPDATE SET n = n - 1;
    INSERT INTO queue_status_counts (status, lane, blocked, n)
        VALUES (NEW.status, NEW.lane, NEW.blocked, 1)
    ON CONFLICT (status, lane, blocked) DO UPDATE SET n = n + 1;
END;

-- The repair pass's candidate set: only completed rows that have not been
-- shape-checked. Once the backlog drains the index is empty and the alarm
-- pays one index probe for it.
CREATE INDEX IF NOT EXISTS idx_queue_shape_requeue
ON queue (task_id) WHERE status = 'completed' AND shape_requeue = 0;

CREATE INDEX IF NOT EXISTS idx_queue_dependencies_dep
ON queue_dependencies (depends_on_task_id);

-- Edges whose dep identity was never resolved can never be met — the
-- blocked-count query reads exactly the `idx_queue_dependencies_unresolved`
-- set. That index, `idx_queue_dependencies_slice` and
-- `idx_queue_dependencies_dep_match` live in
-- `migrate_queue_dependencies_columns` instead of here: a dev-era edges
-- table only gains `dep_crate_name`/`dep_host_side`/`dep_target` there,
-- so an index on them cannot build during this include.

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
    -- The index generation the last applied report declared its base+1:
    -- the optimistic token a delta report's `base_generation` is checked
    -- against (a mismatch is a 409 and the reporter resyncs with a full
    -- report). 0 until the first report applies.
    applied_generation INTEGER NOT NULL DEFAULT 0,
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

-- The schema version this queue was migrated to, kept as a singleton
-- row. `PRAGMA user_version` would be the conventional carrier but the
-- Durable Object SQL authorizer refuses it, so the operator migrate
-- route reads and stamps this row instead (see SCHEMA_VERSION in
-- queue.rs).
CREATE TABLE IF NOT EXISTS scheduler_schema_version (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
);

-- Operator-flipped settings and the breaker-set freeze record.
-- `dispatch_freeze` holds the serialized `DispatchFreezeRecord` the
-- breaker writes on a trip and `dispatch-freeze clear` removes; absent
-- means dispatch is live.
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- The sliding window the dispatch-freeze breaker evaluates. A queue row
-- cannot carry this: a retried task flips back to 'pending' and its
-- earlier failures would vanish from any row-keyed scan, so the outcome
-- tally is kept aside, in per-target time buckets.
-- The breaker's sliding window lives in counters, not rows: every
-- completion upserts one 5-minute bucket per target, so the trip check
-- sums at most (window / 5min) rows per target whatever the traffic.
-- `bucket` is unixepoch floored to the bucket size.
CREATE TABLE IF NOT EXISTS attempt_outcome_buckets (
    target TEXT NOT NULL,
    bucket INTEGER NOT NULL,
    outcomes INTEGER NOT NULL,
    failures INTEGER NOT NULL,
    PRIMARY KEY (target, bucket)
);

-- Raw outcome rows are kept for failures only — the class and
-- example-run evidence the trip alert prints is read once, when the
-- check trips, so successes never land here and failures expire with
-- the window (the completion insert deletes what aged out).
CREATE TABLE IF NOT EXISTS attempt_outcomes (
    task_id TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    -- Compilation target — the breaker's per-target trip streams group
    -- on it.
    target TEXT NOT NULL,
    -- 'build' | 'publish' | 'register' — the pipeline step the old CI
    -- completion report carried. Never written since the route's
    -- removal; kept for the rows that predate it.
    failure_step TEXT,
    -- The failure's error first line (or `unknown`) — what the trip
    -- alert groups failures by.
    failure_class TEXT,
    github_run_id TEXT,
    finished_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (task_id, attempt)
);

-- The trip evidence reads and the expiry delete both bound on
-- finished_at — the index keeps those scans off the row payload.
CREATE INDEX IF NOT EXISTS idx_attempt_outcomes_finished
ON attempt_outcomes (finished_at);


-- The dispatch-freeze transition log the watchdog (#450) turns into the
-- `incident` issue record: one append-only row per engage/clear so a
-- recorder that missed a transition still sees it. `trigger` is the
-- serialized DispatchFreezeTrigger — set on engage and echoed on clear
-- (the cleared record's trigger).
CREATE TABLE IF NOT EXISTS dispatch_freeze_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    event TEXT NOT NULL, -- 'engaged' | 'cleared'
    trigger TEXT         -- serialized DispatchFreezeTrigger, NULL when unknown
);

-- The DO's own billed SQL work, per UTC day — the self-meter the
-- event-driven cost trip reads (GraphQL analytics used to do this on a
-- cron; the DO sees its own cursor rowsRead/rowsWritten immediately and
-- for free). Two statements per request max: one upsert, one read.
CREATE TABLE IF NOT EXISTS do_meter (
    day TEXT PRIMARY KEY,
    rows_read INTEGER NOT NULL,
    rows_written INTEGER NOT NULL
);
