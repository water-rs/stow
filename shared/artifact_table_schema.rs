pub struct RequiredSqlColumn {
    pub name: &'static str,
    pub add_sql: &'static str,
}

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
];
