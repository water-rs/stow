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
    -- Dispatch generation is the unique claim identity; `attempt` is the
    -- current retry-cycle counter and may restart when a row is retried.
    attempt INTEGER NOT NULL DEFAULT 1,
    -- Unique claim identity. It is minted at claim time, so a late
    -- external response cannot match a purged and recreated task row.
    generation_id TEXT NOT NULL DEFAULT '',
    not_before TEXT NOT NULL DEFAULT '1970-01-01 00:00:00',
    first_requested_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    -- The GitHub Actions run id bound to the live generation: the
    -- claim clears it and the dispatch writes it from the
    -- `workflow_dispatch` response's `workflow_run_id`, so a
    -- `workflow_run` completion applies only to the run the in-flight
    -- generation actually dispatched — a stale run's late report is a
    -- conflict, never a silent overwrite. Terminal rows keep the last
    -- bound id as evidence (`stow-admin status` renders its URL).
    github_run_id TEXT,
    -- The unit's compile side: 1 for a host-side node (a proc-macro,
    -- build dependency or build-script unit — minted on the runner
    -- family's host triple and built the way consumers compile it as a
    -- host unit), 0 for a target-side node. Part of the identity: the
    -- same crate legitimately exists at both sides of one triple.
    host_side INTEGER NOT NULL DEFAULT 0,
    -- NULL is historical context that was never recorded, not a leaf.
    dependency_identity TEXT,
    -- Repair latch: 1 once a `completed` row has been re-queued because a
    -- dependent's edge required unit shapes its published rows never
    -- covered (shapeless legacy rows satisfy no gate clause). The
    -- re-queue is at most once — the rebuild republishes real shapes, so
    -- the missing-shape condition cannot recur.
    shape_requeue INTEGER NOT NULL DEFAULT 0,
    -- The owner's count of unmet dependency edges — edges whose
    -- `dep_met` is 0 — maintained as a counter: set at insert, ±1'd by
    -- slice deltas on the edges they flip, and recounted on edge resync
    -- (stow#521). The gate never re-evaluates the edge set to know
    -- whether a row is blocked: `deps_met` is `unpublished_deps = 0`,
    -- and a publish touches the changed rows' matched edges plus their
    -- owners, never every dependent's whole edge list.
    unpublished_deps INTEGER NOT NULL DEFAULT 0,
    -- The dependency gate's answer, persisted: 1 while every edge of this
    -- row resolves to units the published slice serves — the stored form
    -- of `unpublished_deps = 0`, derived wherever the counter is
    -- written (insert, edge resync, slice delta, migration) and kept
    -- current by every transition into `pending` — the claim reads the
    -- flag only on pending rows, so a dispatch pass never re-evaluates
    -- the dependency EXISTS.
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
    -- The demand the claim order descends on before cost (stow#442
    -- I6): precedence bands over `priority` and `demand` — two bands
    -- for the human lane, one for the Windows family — so lane,
    -- family and the banded operands compare inside one integer. The
    -- dispatch key orders on the whole value divided by expected
    -- build cost; this column keeps the undivided value. Refreshed
    -- with `dispatch_key` wherever a lane, priority or demand operand
    -- changes (re-request, promote, revive, demand fold); the family
    -- never changes after insert.
    value INTEGER NOT NULL DEFAULT 0,
    -- Accumulated observed demand (stow#522): the sum of this task's
    -- `demand_contributions` rows, written only by the demand route.
    -- It is a `value` operand inside the priority band — the band
    -- bound keeps `priority + demand <= PRIORITY_MAX` — so every key
    -- refresh and re-request carries it forward instead of wiping it.
    demand INTEGER NOT NULL DEFAULT 0,
    -- The claim ORDER BY tuple encoded as one sortable string:
    -- lane prefix (0 human / 1 other) | fixed-64 lowercase hex of the
    -- inverted exact rank quotient U256::MAX - floor((value << 128) /
    -- expected_cost) | first_requested_at | created_at | task_id.
    -- The quotient preserves the full rational order of
    -- value / (crate_name, target) median build cost (stow#524 —
    -- cheap expected builds claim first at equal value); the lane
    -- prefix keeps human precedence literal, and equal quotients fall
    -- through to the FIFO tie-breakers. The claim walk orders by it
    -- under an index and pages by keyset, so a dispatch pass reads
    -- rows proportional to the slots it fills, not the queue size.
    dispatch_key TEXT NOT NULL DEFAULT '',
    -- The instant this row's live generation was claimed — written
    -- only by the claim UPDATE, so it is immutable for the generation
    -- while `updated_at` is rewritten by every in-flight writer (a
    -- re-request bumps it even on an active row). `NULL` until first
    -- claim and on rows migrated from before the column: a completion
    -- only samples duration against a real claim stamp (stow#524).
    claimed_at TEXT,
    -- The admission floor's persisted answer (stow#525 I10):
    -- `lane = 'human' OR value >= floor`, with `floor` the
    -- `min_dispatch_value` row `settings` carries — the value the last
    -- operator migrate stamped, never a request-time read. Maintained
    -- by every writer that touches `value` or `lane`, and equality-
    -- indexed ahead of the order/range fields so a positive floor
    -- excludes the under-floor bulk before any rank or wake walk
    -- reaches it.
    dispatch_eligible INTEGER NOT NULL DEFAULT 1,
    UNIQUE(crate_name, version, features_json, target, rustc_version, host_side, dependency_identity)
);

-- Status and lane are the queue's hot predicates: status() groups by them,
-- claim and recover filter on them.
CREATE INDEX IF NOT EXISTS idx_queue_status_lane
ON queue (status, lane);

-- Request status positions count a human lane prefix by dispatch key.
-- Keep lane before the range key so the bounded human-depth walk does not
-- scan pending miss rows; all selected columns are covered by the index.
CREATE INDEX IF NOT EXISTS idx_queue_human_position
ON queue (status, lane, dispatch_key);

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
    dep_dependency_identity TEXT,
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
    -- The edge's own gate answer, persisted: 1 while the live published
    -- slice for the dep's (dep_target, dep_rustc_version) serves every
    -- unit shape the mask requires — the row form of
    -- dep_edge_unpublished_sql. Written at insert, flipped by slice
    -- deltas on the edges they match, backfilled by the migration — so
    -- the owner's `unpublished_deps` counter can move by ±1 on a flip
    -- instead of re-evaluating the slice join per edge.
    dep_met INTEGER NOT NULL DEFAULT 0,
    -- Whether the edge's required side is established — resolver-written
    -- edges carry 1, legacy rows the side migration derives stamp their
    -- outcome and mark themselves known so it runs once.
    dep_side_known INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (task_id, depends_on_task_id)
);

-- One demand batch's durable record (stow#522): the batch/window
-- identity and payload contract the hourly demand feed (#523) replays
-- against. `input_hash` is the blake3 fingerprint of the canonical
-- (sorted, summed) entry set — a redelivery naming this id must carry
-- the same fingerprint or fail, draft or accepted — and `state` is the
-- typed lifecycle: `prepared` is an unaccepted draft whose staging a
-- same-input retry may replace, `accepted` is a complete batch whose
-- replay answers from this header and writes nothing. The
-- contribution set itself is never stored here — it lives
-- relationally in demand_contributions, so no row approaches the
-- platform's string/row size bound.
CREATE TABLE IF NOT EXISTS demand_batches (
    batch_id TEXT PRIMARY KEY,
    input_hash TEXT NOT NULL,
    -- The staged (task, delta) count recorded at acceptance: the
    -- trigger's staged-count verification and the replay report's
    -- touched count.
    touched_count INTEGER NOT NULL CHECK (touched_count >= 0),
    state TEXT NOT NULL DEFAULT 'prepared'
        CHECK (state IN ('prepared', 'accepted')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- One demand batch's contribution to one task (stow#522): the
-- event-local staging set — relational rows, never a serialized blob.
-- Rows under a `prepared` batch are unaccepted draft material a
-- reprepare may clear wholesale; the guarded `prepared → accepted`
-- UPDATE on demand_batches fires the `demand_fold` trigger (created at
-- migrate), which folds every staged row into the queue inside that
-- one statement — statement-atomic acceptance, so an accepted batch
-- has no unapplied remainder and a replay writes nothing. The staged
-- `value`, `dispatch_key` and `dispatch_eligible` are the event's
-- PRECOMPUTED answers — derived in Rust through the shared rank
-- abstraction at the post-fold demand before a single ledger write —
-- so the trigger is a static prepared-field copy and no ranking
-- formula exists in SQL anywhere. Acceptance consumes the staged set:
-- `demand_fold` retires this batch's rows in the same statement after
-- the fold verifies the count, because an accepted batch's replay
-- reads only the header (stow#523 — the recurring feed would
-- otherwise accumulate dead staging rows forever); a `prepared` draft
-- keeps every staged row for accept-or-retry.
CREATE TABLE IF NOT EXISTS demand_contributions (
    task_id TEXT NOT NULL,
    -- The batch's durable window identity (e.g. the feed hour).
    batch_id TEXT NOT NULL,
    -- This batch's total contribution to the task — the sum of every
    -- entry in the batch whose closure reached it.
    delta INTEGER NOT NULL CHECK (delta >= 0),
    -- The task's post-fold raw value, as decimal text (the integer
    -- range exceeds a JS Number's exact band).
    value TEXT NOT NULL,
    -- The task's post-fold dispatch key — exact-rank prefix plus the
    -- FIFO fields the queue row already carries.
    dispatch_key TEXT NOT NULL,
    -- The task's post-fold admission answer under the stored floor.
    dispatch_eligible INTEGER NOT NULL CHECK (dispatch_eligible IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (task_id, batch_id)
);

-- The demand path reads only a batch's own rows — the fold and the
-- bound probe are driven by this index, never the stored ledger.
CREATE INDEX IF NOT EXISTS idx_demand_contributions_batch
ON demand_contributions (batch_id);

-- One demand-feed hour's durable header (stow#523). `state` is the
-- typed lifecycle: `staging` holds an incomplete materialization a
-- same-generation resume continues, `complete` is a frozen hour — its
-- staged page payloads are immutable input, delivery replays them
-- verbatim and never re-queries Analytics Engine — and `delivered` is
-- terminal, every original page acknowledged. `generation` identifies
-- the staging attempt: pages and the complete barrier bind to it, so
-- a restarted attempt cannot mix its bytes into a frozen hour, and a
-- frozen hour's begin refuses. The header is compact forever — it is
-- the replay proof an old-hour delivery dedupes against — and carries
-- no retention clock.
CREATE TABLE IF NOT EXISTS demand_feed_hours (
    hour TEXT PRIMARY KEY,
    generation INTEGER NOT NULL CHECK (generation > 0),
    state TEXT NOT NULL DEFAULT 'staging'
        CHECK (state IN ('staging', 'complete', 'delivered')),
    -- Live staging counters — maintained atomically by the page
    -- insert/apply triggers, so a page call and a header counter can
    -- never disagree, and the completion barrier reads the header
    -- instead of rescanning the generation's pages.
    staged_pages INTEGER NOT NULL DEFAULT 0 CHECK (staged_pages >= 0),
    staged_entries INTEGER NOT NULL DEFAULT 0 CHECK (staged_entries >= 0),
    applied_pages INTEGER NOT NULL DEFAULT 0 CHECK (applied_pages >= 0),
    -- The frozen manifest the completion barrier verified: page count
    -- and total entries across this generation's pages. Proving all
    -- pages staged BEFORE the freeze is the barrier's job — this is
    -- the recorded result, not a header stamp a later page write could
    -- drift from.
    page_count INTEGER NOT NULL DEFAULT 0 CHECK (page_count >= 0),
    entry_count INTEGER NOT NULL DEFAULT 0 CHECK (entry_count >= 0),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- One staged page of a demand-feed hour's frozen input (stow#523):
-- the bounded immutable payload (≤256 entries, ≤512 KiB serialized —
-- under the 100-bind / statement-size / row-size native limits) plus
-- its `applied` mark. `page_hash` (blake3 of the payload) makes the
-- page immutable: a same-page replay with identical bytes is a no-op
-- and a changed payload refuses. `chain_hash` is the rolling blake3
-- `chain(p) = blake3(chain(p-1) || page_hash(p))` seeded by page 0 —
-- the completion barrier binds the frozen set to the one ordered
-- manifest the materializer validated. Delivery replays the payload
-- into the demand batch `demand-feed/{hour}/{page_no}` and flips
-- `applied` only after the batch reports — a lost ack re-arms the
-- same page, which the demand ledger answers as a zero-write
-- accepted replay. Rows retire in bounded chunks after the hour
-- delivers and the watermark makes every older replay a no-op:
-- payloads live exactly as long as unacknowledged delivery needs them.
CREATE TABLE IF NOT EXISTS demand_feed_pages (
    hour TEXT NOT NULL,
    generation INTEGER NOT NULL,
    page_no INTEGER NOT NULL CHECK (page_no >= 0),
    entry_count INTEGER NOT NULL CHECK (entry_count > 0),
    page_hash TEXT NOT NULL,
    chain_hash TEXT NOT NULL,
    payload TEXT NOT NULL,
    applied INTEGER NOT NULL DEFAULT 0 CHECK (applied IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (hour, generation, page_no),
    FOREIGN KEY (hour) REFERENCES demand_feed_hours(hour)
);

-- Page insert and header counters in the same statement: a staged
-- page and the hour's `staged_pages`/`staged_entries` can never
-- disagree. Fires only on INSERT — a begin-rotation's page delete or
-- an `applied` flip never touches them.
CREATE TRIGGER IF NOT EXISTS demand_feed_page_stage
AFTER INSERT ON demand_feed_pages
BEGIN
    UPDATE demand_feed_hours
    SET staged_pages = staged_pages + 1,
        staged_entries = staged_entries + NEW.entry_count
    WHERE hour = NEW.hour;
END;

-- The `applied` flip and the hour's `applied_pages` counter in the
-- same statement — the deliver walk reads the header, never a COUNT
-- over every remaining page.
CREATE TRIGGER IF NOT EXISTS demand_feed_page_apply
AFTER UPDATE OF applied ON demand_feed_pages
WHEN NEW.applied = 1 AND OLD.applied = 0
BEGIN
    UPDATE demand_feed_hours
    SET applied_pages = applied_pages + 1
    WHERE hour = NEW.hour;
END;

-- The `delivered` transition stamps the durable watermark in the same
-- statement — a restart can never observe a delivered hour without its
-- cursor. The `excluded.value > settings.value` guard keeps the
-- cursor monotonic: an out-of-order or replayed delivery can never
-- move it backwards. Contiguity (only the canonical next hour may
-- deliver) is enforced by the guarded transition statement itself.
CREATE TRIGGER IF NOT EXISTS demand_feed_hour_delivered
AFTER UPDATE OF state ON demand_feed_hours
WHEN NEW.state = 'delivered'
BEGIN
    INSERT INTO settings (key, value) VALUES ('demand_feed_watermark', NEW.hour)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
    WHERE excluded.value > settings.value;
END;

-- The durable resume cursor's unfinished half: at most one row per
-- non-terminal hour (`staging` or `complete`), so the feed's status
-- read is a bounded index probe — never a scan over delivered
-- headers.
CREATE INDEX IF NOT EXISTS idx_demand_feed_unfinished
ON demand_feed_hours (hour)
WHERE state IN ('staging', 'complete');

-- The deliver walk's per-hour page scan.
CREATE INDEX IF NOT EXISTS idx_demand_feed_pages_pending
ON demand_feed_pages (hour, generation, applied, page_no);

-- The claim walk: pending + deps-met rows in dispatch order. The alarm's
-- dispatch pass reads the first page of this index, never the queue.
-- `dispatch_key` is unique within a status group, so the trailing
-- residual-filter columns (`dispatch_family`, `lane`,
-- `first_requested_at`, `not_before`) do not disturb the ORDER BY — they
-- let a skipped index entry answer the family/lane/age checks without
-- fetching the row. `dispatch_eligible` leads the ordering fields so a
-- positive admission floor excludes the under-floor bulk before the
-- `dispatch_key` walk reads it (stow#525).
CREATE INDEX IF NOT EXISTS idx_queue_claim
ON queue (status, deps_met, dispatch_eligible, dispatch_key, dispatch_family, lane, first_requested_at, not_before);

-- The alarm's wake probes: `SELECT 1 … wake_at <= now LIMIT 1` (already
-- dispatchable) and `MIN(wake_at) … wake_at > now` (earliest deferred
-- wake) — both bounded by the `wake_at` ordering, with
-- `dispatch_family` before it so a saturated family's deferred rows do
-- not stand ahead of another family's earliest wake in the same walk.
-- `dispatch_eligible` precedes the range field, so a queue of
-- under-floor rows is excluded by equality before the `wake_at` walk —
-- no bulk read against the floor (stow#525).
CREATE INDEX IF NOT EXISTS idx_queue_wake
ON queue (status, deps_met, dispatch_eligible, dispatch_family, wake_at);

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
    dependency_identity TEXT,
    -- The unit shape the row serves — the builder-recorded side, cargo
    -- invocation spelling, and link kind the dependency gate compares an
    -- edge's required shapes against. -1 on all three legs marks a row
    -- reported before the columns existed: shapeless rows satisfy no
    -- coverage clause and the dependent stays gated until the node
    -- rebuilds and republishes.
    unit_side INTEGER NOT NULL DEFAULT -1,
    unit_invocation INTEGER NOT NULL DEFAULT -1,
    unit_linked INTEGER NOT NULL DEFAULT -1,
    PRIMARY KEY (target, rustc_version, generation, crate_name, version, features_json, dependency_identity, unit_side, unit_invocation, unit_linked)
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

-- Generation-keyed failure evidence. This table is additive so an older
-- Worker may continue inserting the legacy attempt_outcomes columns while
-- the new code rolls out; freeze evidence reads both tables.
CREATE TABLE IF NOT EXISTS attempt_outcomes_v2 (
    task_id TEXT NOT NULL,
    generation_id TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    target TEXT NOT NULL,
    failure_step TEXT,
    failure_class TEXT,
    github_run_id TEXT,
    finished_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (task_id, generation_id)
);

CREATE INDEX IF NOT EXISTS idx_attempt_outcomes_v2_finished
ON attempt_outcomes_v2 (finished_at);

-- A verified workflow completion can beat the scheduler's write of the
-- `workflow_dispatch` response. Keep that event by the run identity until
-- the exact response binds the same run to the claimed generation. Rows are
-- bounded by in-flight dispatches and are deleted when the binding applies
-- or the unbound generation is abandoned.
CREATE TABLE IF NOT EXISTS pending_run_completions (
    github_run_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    success INTEGER NOT NULL CHECK (success IN (0, 1)),
    error TEXT,
    received_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_pending_run_completions_task
ON pending_run_completions (task_id);


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

-- The human request lane's records (stow#428): one row per admitted
-- `POST /api/v1/requests`, moved `accepted` -> `resolving` ->
-- `enqueued` | `failed` by the resolve run's outcome report and the
-- workflow_run backstop. `outcome_json` holds the per-target stored
-- roots the status read re-probes against the live queue; `dispatched_at`
-- is the resolve job's dispatch-to-submit timing baseline.
CREATE TABLE IF NOT EXISTS requests (
    request_id TEXT PRIMARY KEY,
    attempt INTEGER NOT NULL,
    crate_name TEXT NOT NULL,
    version TEXT NOT NULL,
    features_json TEXT NOT NULL,
    rustc_version TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('accepted', 'resolving', 'enqueued', 'failed')),
    dispatched_at INTEGER, -- unixepoch seconds of the dispatch POST
    github_run_id TEXT,
    github_run_url TEXT,
    outcome_json TEXT,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- One successful build's claim-to-completion duration, bound to the
-- claim generation that ran it (stow#524): a late, duplicate or
-- old-generation report can never re-land a sample — the generation
-- is consumed by the completion fence before sampling runs, and the
-- PRIMARY KEY dedups any replay that still arrives. The window per
-- (crate_name, target) is the newest BUILD_SAMPLE_WINDOW samples by
-- insertion; each completion deletes the tail past it, so a key
-- never outgrows the window and the median below never scans history.
CREATE TABLE IF NOT EXISTS crate_build_samples (
    crate_name TEXT NOT NULL,
    target TEXT NOT NULL,
    generation_id TEXT NOT NULL,
    duration_ms INTEGER NOT NULL CHECK (duration_ms >= 0),
    PRIMARY KEY (crate_name, target, generation_id)
);

-- The per-(crate, target) expected build cost the rank divides the
-- row's whole `value` by — precedence and family bands included,
-- so a cheaper build moves its lane peers ahead only within the
-- same value: `builds` counts every accepted sample, `median_ms` is
-- the lower median of the live sample window, recomputed from at
-- most BUILD_SAMPLE_WINDOW rows per completion — never a historical
-- scan. The dispatch_key score probes this table once per row a
-- write touches; a key absent here costs 1, so unmeasured crates
-- keep their full demand value.
CREATE TABLE IF NOT EXISTS crate_build_stats (
    crate_name TEXT NOT NULL,
    target TEXT NOT NULL,
    builds INTEGER NOT NULL,
    median_ms INTEGER NOT NULL,
    PRIMARY KEY (crate_name, target)
);

-- The cost-move refresh's exact probe: `WHERE status = 'pending'
-- AND crate_name = ? AND target = ?`. Without it the refresh falls
-- back to `idx_queue_crate_updated` (crate_name only) and reads the
-- crate's whole history — every completed, failed and other-target
-- row — instead of just the pending set it may rewrite.
CREATE INDEX IF NOT EXISTS idx_queue_pending_crate_target
ON queue (crate_name, target) WHERE status = 'pending';
