-- stow#367: a miss keys on the identity the queue deduplicates on —
-- crate, version, features, target, rustc, SIDE. The 5-tuple primary
-- key made a host miss and a target miss at one semantic identity
-- collide on `ON CONFLICT`, and a drained row minted
-- `EnqueueRequest{host_side:false}` whatever its real side was —
-- the wrong-side task answered the drain and the true gap was
-- dropped. Rebuild the table with `host_side` in the primary key;
-- every pre-existing row is target-side by definition (nothing could
-- record a host one).
ALTER TABLE dependency_graph_misses RENAME TO dependency_graph_misses_legacy;

CREATE TABLE dependency_graph_misses (
    crate_name TEXT NOT NULL,
    version TEXT NOT NULL,
    features_json TEXT NOT NULL,
    target TEXT NOT NULL,
    rustc_version TEXT NOT NULL,
    host_side INTEGER NOT NULL DEFAULT 0,
    seen_count INTEGER NOT NULL DEFAULT 0,
    first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    admitted_at TEXT,
    queued_at TEXT,
    depends_on_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (crate_name, version, features_json, target, rustc_version, host_side)
);

INSERT INTO dependency_graph_misses
    (crate_name, version, features_json, target, rustc_version, seen_count,
     first_seen_at, last_seen_at, admitted_at, queued_at, depends_on_json)
    SELECT crate_name, version, features_json, target, rustc_version, seen_count,
           first_seen_at, last_seen_at, admitted_at, queued_at, depends_on_json
    FROM dependency_graph_misses_legacy;

DROP TABLE dependency_graph_misses_legacy;

CREATE INDEX IF NOT EXISTS idx_dependency_graph_misses_target
ON dependency_graph_misses (target, rustc_version, last_seen_at);
