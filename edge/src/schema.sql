CREATE TABLE IF NOT EXISTS artifacts (
    compile_key TEXT NOT NULL,
    c_metadata TEXT NOT NULL,
    extra_filename TEXT NOT NULL,
    target TEXT NOT NULL,
    rustc_version TEXT NOT NULL,
    crate_name TEXT NOT NULL,
    version TEXT NOT NULL,
    features_json TEXT NOT NULL,
    dependency_c_metadata_json TEXT NOT NULL DEFAULT '[]',
    oci_reference TEXT NOT NULL,
    oci_digest TEXT NOT NULL,
    has_native INTEGER NOT NULL DEFAULT 0,
    artifact_kind TEXT NOT NULL,
    crate_types_json TEXT NOT NULL,
    profile_json TEXT NOT NULL,
    emit_json TEXT NOT NULL,
    artifact_size INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (c_metadata, target, rustc_version)
);

CREATE INDEX IF NOT EXISTS idx_artifacts_catalog
ON artifacts (target, rustc_version, crate_name, features_json, version);

CREATE TABLE IF NOT EXISTS subscriptions (
    crate_name TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cache_misses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crate_name TEXT NOT NULL,
    c_metadata TEXT NOT NULL,
    target TEXT NOT NULL,
    city_code TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cache_misses_crate_target
ON cache_misses (crate_name, target, created_at);

CREATE TABLE IF NOT EXISTS dependency_graph_misses (
    crate_name TEXT NOT NULL,
    version TEXT NOT NULL,
    features_json TEXT NOT NULL,
    target TEXT NOT NULL,
    rustc_version TEXT NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 0,
    first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    admitted_at TEXT,
    queued_at TEXT,
    PRIMARY KEY (crate_name, version, features_json, target, rustc_version)
);

CREATE INDEX IF NOT EXISTS idx_dependency_graph_misses_target
ON dependency_graph_misses (target, rustc_version, last_seen_at);

-- Canonical enqueue payloads behind outstanding miss admissions. Populated
-- when a miss response mints an EnqueueAdmission; /api/v1/enqueue looks the
-- request up by task_id. Rows older than the challenge window are dead.
CREATE TABLE IF NOT EXISTS pending_admissions (
    task_id TEXT PRIMARY KEY,
    request_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS crate_versions_cache (
    crate_name TEXT PRIMARY KEY,
    versions_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS crate_version_graph_cache (
    crate_name TEXT NOT NULL,
    version TEXT NOT NULL,
    graph_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (crate_name, version)
);