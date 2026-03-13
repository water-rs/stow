CREATE TABLE IF NOT EXISTS queue (
    task_id TEXT PRIMARY KEY,
    crate_name TEXT NOT NULL,
    version TEXT NOT NULL,
    target TEXT NOT NULL,
    downloads INTEGER NOT NULL DEFAULT 0,
    miss_count INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    gh_run_id TEXT,
    error_msg TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(crate_name, version, target)
);
