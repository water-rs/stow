//! Shared SQL schema migration list for the artifacts table.
//!
//! Both the edge worker (D1) and the mock registry (local `SQLite`) keep their
//! `artifacts` table aligned via this list of incremental ALTER statements.

/// One column the `artifacts` table is required to have. The migration runner
/// iterates and `ALTER TABLE` adds any missing entry.
#[derive(Debug)]
pub struct RequiredSqlColumn {
    /// Column name as it appears in `PRAGMA table_info(artifacts)`.
    pub name: &'static str,
    /// `ALTER TABLE` SQL to add the column when missing.
    pub add_sql: &'static str,
}

/// Every column the `artifacts` table must carry, in migration order.
///
/// Edge (D1) and the mock registry (SQLite) both iterate this list to add
/// missing columns; append new columns here rather than editing existing
/// `add_sql` strings, which old databases have already run.
pub const REQUIRED_ARTIFACT_COLUMNS: &[RequiredSqlColumn] = &[
    RequiredSqlColumn {
        name: "compile_key",
        add_sql: "ALTER TABLE artifacts ADD COLUMN compile_key TEXT NOT NULL DEFAULT ''",
    },
    RequiredSqlColumn {
        name: "extra_filename",
        add_sql: "ALTER TABLE artifacts ADD COLUMN extra_filename TEXT NOT NULL DEFAULT ''",
    },
    RequiredSqlColumn {
        name: "has_native",
        add_sql: "ALTER TABLE artifacts ADD COLUMN has_native INTEGER NOT NULL DEFAULT 0",
    },
    RequiredSqlColumn {
        name: "artifact_kind",
        add_sql: "ALTER TABLE artifacts ADD COLUMN artifact_kind TEXT NOT NULL DEFAULT 'rlib'",
    },
    RequiredSqlColumn {
        name: "crate_types_json",
        add_sql: "ALTER TABLE artifacts ADD COLUMN crate_types_json TEXT NOT NULL DEFAULT '[]'",
    },
    RequiredSqlColumn {
        name: "profile_json",
        add_sql: "ALTER TABLE artifacts ADD COLUMN profile_json TEXT NOT NULL DEFAULT '{}'",
    },
    RequiredSqlColumn {
        name: "emit_json",
        add_sql: "ALTER TABLE artifacts ADD COLUMN emit_json TEXT NOT NULL DEFAULT '[]'",
    },
    RequiredSqlColumn {
        name: "created_at",
        add_sql: "ALTER TABLE artifacts ADD COLUMN created_at TEXT NOT NULL DEFAULT ''",
    },
    RequiredSqlColumn {
        name: "dependency_c_metadata_json",
        add_sql: "ALTER TABLE artifacts ADD COLUMN dependency_c_metadata_json TEXT NOT NULL DEFAULT '[]'",
    },
    RequiredSqlColumn {
        name: "dependency_count",
        add_sql: "ALTER TABLE artifacts ADD COLUMN dependency_count INTEGER NOT NULL DEFAULT -1",
    },
    RequiredSqlColumn {
        name: "bundle_digest",
        add_sql: "ALTER TABLE artifacts ADD COLUMN bundle_digest TEXT NOT NULL DEFAULT ''",
    },
    RequiredSqlColumn {
        name: "bundle_size",
        add_sql: "ALTER TABLE artifacts ADD COLUMN bundle_size INTEGER NOT NULL DEFAULT 0",
    },
    RequiredSqlColumn {
        name: "compile_millis",
        add_sql: "ALTER TABLE artifacts ADD COLUMN compile_millis INTEGER NOT NULL DEFAULT 0",
    },
];
