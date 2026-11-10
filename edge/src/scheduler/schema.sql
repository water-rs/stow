-- stow#878: the scheduler's whole durable state. The dependency graph
-- lives in memory; this is the flat substrate it survives a forced
-- eviction by. `event_log` is the append-only log — one row per
-- accepted event, stamped with the instant it was accepted at and
-- dropped to the watermark after each snapshot; `snapshot_chunks`
-- carries the chunked serialized graph; `store_meta` holds the
-- snapshot watermark. `node_digests` holds the dependency digest of
-- every node that has queue state, one row per state slot: `digest` is
-- the 64 hex digits the node's task id spells. A merge upserts the rows
-- of its fresh slots in the turn that appends its log rows, a reused
-- slot is overwritten, a vacant slot's stale row is harmless until its
-- reuse, and a replay writes nothing. `meter` (stow#931) is the one-row checkpoint of
-- the day's billed totals — `seq` is the last `event_log` seq whose
-- append they already cover; request code and the alarm only UPDATE
-- the row, never create it.
CREATE TABLE IF NOT EXISTS event_log (
    seq INTEGER PRIMARY KEY,
    at INTEGER NOT NULL,
    event TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshot_chunks (
    chunk INTEGER PRIMARY KEY,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS store_meta (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS node_digests (
    slot INTEGER PRIMARY KEY,
    digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meter (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    day TEXT NOT NULL,
    rows_read INTEGER NOT NULL,
    rows_written INTEGER NOT NULL,
    seq INTEGER NOT NULL
);
INSERT INTO meter VALUES (0, '', 0, 0, 0);