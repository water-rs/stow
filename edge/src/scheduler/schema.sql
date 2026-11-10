-- stow#878: the scheduler's whole durable state. The dependency graph
-- lives in memory; this is the flat substrate it survives a forced
-- eviction by. `event_log` is the append-only log — one row per
-- accepted event, stamped with the instant it was accepted at and
-- dropped to the watermark after each snapshot; `snapshot_chunks`
-- carries the chunked serialized graph; `store_meta` holds the
-- snapshot watermark. `node_digests` holds the dependency digest of
-- every node that has queue state, by the node's state slot: 256 slots
-- to a row, `block = slot / 256`, `digests` the base64 of 256 fixed
-- 32-byte records. A merge writes the rows of its fresh slots in the
-- turn that appends its log rows, a reused slot is overwritten, and a
-- replay writes nothing. `meter` (stow#931) is the one-row checkpoint of
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
    block INTEGER PRIMARY KEY,
    digests TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meter (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    day TEXT NOT NULL,
    rows_read INTEGER NOT NULL,
    rows_written INTEGER NOT NULL,
    seq INTEGER NOT NULL
);
INSERT INTO meter VALUES (0, '', 0, 0, 0);