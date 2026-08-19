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
    dispatch_attempts INTEGER NOT NULL DEFAULT 0,
    not_before TEXT NOT NULL DEFAULT '1970-01-01 00:00:00',
    first_requested_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(crate_name, version, features_json, target, rustc_version)
);

CREATE TABLE IF NOT EXISTS queue_dependencies (
    task_id TEXT NOT NULL,
    depends_on_task_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (task_id, depends_on_task_id)
);
