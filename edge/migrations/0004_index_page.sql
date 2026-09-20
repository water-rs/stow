-- The admin index endpoint walks each (target, rustc_version) slice
-- ordered by c_metadata, one keyset page at a time; this index turns every
-- page into a bounded range scan instead of a full-slice sort.
CREATE INDEX IF NOT EXISTS idx_artifacts_index_page
ON artifacts (target, rustc_version, c_metadata);
