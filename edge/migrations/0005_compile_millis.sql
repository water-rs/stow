-- Wall-clock milliseconds the captured rustc invocation took, recorded at
-- register time. Rows registered before this carry 0 and count as zero CPU
-- time saved in the usage statistics.
ALTER TABLE artifacts ADD COLUMN compile_millis INTEGER NOT NULL DEFAULT 0;
