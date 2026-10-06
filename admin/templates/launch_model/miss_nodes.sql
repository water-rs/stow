-- Miss nodes: `stow_cache_misses` points are unsampled — one per
-- uncovered node the admissions lane minted a ticket for. The
-- `_sample_interval * double1` product equals `count()` today and
-- stays correct if the dataset ever samples.
SELECT sum(_sample_interval * double1) AS value
FROM stow_cache_misses
WHERE blob1 = 'miss'
  AND timestamp >= toDateTime('{{ window.since }} 00:00:00')
  AND timestamp < toDateTime('{{ window.until }} 00:00:00')
FORMAT JSON
