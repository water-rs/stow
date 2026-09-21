/// D1's bound-parameter ceiling per statement. Every multi-row write and
/// pair-keyed read below chunks so `rows * params_per_row + fixed_params`
/// stays at or under it.
pub const D1_MAX_BOUND_PARAMS: usize = 100;

pub const SQLITE_IN_CLAUSE_BATCH_SIZE: usize = 64;

/// Rows per `crate_version_graph_cache` upsert statement: 3 bound params
/// per row (`crate_name`, `version`, `graph_json`); `fetched_at` is a SQL
/// literal.
pub const VERSION_GRAPH_CACHE_UPSERT_BATCH_SIZE: usize = D1_MAX_BOUND_PARAMS / 3;

/// `(crate_name, version)` pairs per `crate_version_graph_cache` read
/// statement: 2 bound params per pair plus 1 TTL modifier param.
pub const VERSION_GRAPH_CACHE_READ_BATCH_SIZE: usize = (D1_MAX_BOUND_PARAMS - 1) / 2;

/// Rows per `crate_versions_cache` upsert statement: 2 bound params per
/// row (`crate_name`, `versions_json`); `fetched_at` is a SQL literal.
pub const VERSIONS_CACHE_UPSERT_BATCH_SIZE: usize = D1_MAX_BOUND_PARAMS / 2;

/// `crate_name` keys per `crate_versions_cache` read statement: 1 bound
/// param per key plus 1 TTL modifier param.
pub const VERSIONS_CACHE_READ_BATCH_SIZE: usize = D1_MAX_BOUND_PARAMS - 1;

pub fn placeholders(len: usize) -> String {
    assert!(len > 0, "SQL placeholder list must be non-empty");
    std::iter::repeat_n("?", len).collect::<Vec<_>>().join(", ")
}

/// Repeat one `VALUES` row template `rows` times, comma-separated —
/// `(?, ?, ?), (?, ?, ?), …`.
pub fn values_rows(row_template: &str, rows: usize) -> String {
    assert!(rows > 0, "SQL VALUES list must be non-empty");
    std::iter::repeat_n(row_template, rows)
        .collect::<Vec<_>>()
        .join(", ")
}
