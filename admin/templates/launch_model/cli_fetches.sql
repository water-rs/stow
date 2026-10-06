-- Byte-path fetches: hit points carry `double1` as their caller
-- weight — `sum(_sample_interval * double1)` is the additive
-- estimate: exact for unsampled writes (interval 1) and scaled when
-- the engine samples.
SELECT sum(_sample_interval * double1) AS value
FROM stow_events
WHERE blob1 = 'hit'
  AND timestamp >= toDateTime('{{ window.since }} 00:00:00')
  AND timestamp < toDateTime('{{ window.until }} 00:00:00')
FORMAT JSON
