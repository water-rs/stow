/// D1's bound-parameter ceiling per statement. Every multi-row write and
/// pair-keyed read below chunks so `rows * params_per_row + fixed_params`
/// stays at or under it.
pub const D1_MAX_BOUND_PARAMS: usize = 100;

pub const SQLITE_IN_CLAUSE_BATCH_SIZE: usize = 64;

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
