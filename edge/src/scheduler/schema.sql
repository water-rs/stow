-- stow#878: the scheduler's whole durable state. The dependency graph
-- lives in memory; this is the flat substrate it survives a forced
-- eviction by. `event_log` is the append-only log — one row per
-- accepted event, stamped with the instant it was accepted at and
-- dropped to the watermark after each snapshot; `snapshot_chunks`
-- carries the chunked serialized graph; `store_meta` holds the
-- snapshot watermark. `published` (below) holds the index's published
-- masks as of that watermark. `node_digests` holds the dependency digest of
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
-- `published` holds the unit-shape mask of every task id the index
-- serves, as of the snapshot watermark: `slice` is the slice's persisted
-- target and rustc ids (target << 8 | rustc), `key` the 16-byte hash of
-- the task id, `mask` the shapes served. A key lives in one slice, since
-- its task id embeds the target and rustc. Ordered by slice then key, so
-- a point lookup and a slice listing each read only the rows they
-- return. Only a snapshot's storage turn writes it (an upsert for a
-- non-zero mask, a delete for zero); the graph holds the changes since
-- and a replay rebuilds them from the log tail. The table refills from
-- the slice reports after a reset.
CREATE TABLE IF NOT EXISTS published (
    slice INTEGER NOT NULL,
    key BLOB NOT NULL,
    mask INTEGER NOT NULL,
    PRIMARY KEY (slice, key)
) WITHOUT ROWID;
-- `backlog` (stow#1501) holds the submissions the graph's memory lines
-- had no room for, verbatim: one row per `Submit` part of a tree, in
-- the JSON the event log would hold it as, so admitting an entry
-- appends its rows to `event_log` unchanged. `seq` is the arrival
-- order and an entry's parts are consecutive; `lane` ranks the entry
-- points for admission (0 the human lane, 1 operations, 2 the CLI's
-- misses, 3 preheat) and FIFO holds within one lane by `seq`. `parts`
-- is the entry's part count, on every row; `actor` is the verified
-- run behind the first part's request. The count and bytes of the
-- entries held live in `store_meta` (`backlog_entries_<lane>` and
-- `backlog_bytes`), moved in the turn that writes or deletes the rows.
CREATE TABLE IF NOT EXISTS backlog (
    seq INTEGER PRIMARY KEY,
    lane INTEGER NOT NULL,
    part INTEGER NOT NULL,
    parts INTEGER NOT NULL,
    actor TEXT,
    event TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS backlog_lane ON backlog(lane, seq);
CREATE TABLE IF NOT EXISTS meter (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    day TEXT NOT NULL,
    rows_read INTEGER NOT NULL,
    rows_written INTEGER NOT NULL,
    seq INTEGER NOT NULL
);
INSERT INTO meter VALUES (0, '', 0, 0, 0);