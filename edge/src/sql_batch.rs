pub const SQLITE_IN_CLAUSE_BATCH_SIZE: usize = 64;

pub fn placeholders(len: usize) -> String {
    assert!(len > 0, "SQL placeholder list must be non-empty");
    std::iter::repeat("?")
        .take(len)
        .collect::<Vec<_>>()
        .join(", ")
}
