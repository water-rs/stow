-- Distinct installs over the window: `stow_events.index1` is the
-- daily-salted install hash, so distinct values over the window count
-- install-days. Askama substitutes only the typed QueryWindow bounds.
SELECT count(DISTINCT index1) AS value
FROM stow_events
WHERE blob1 = 'hit'
  AND timestamp >= toDateTime('{{ window.since }} 00:00:00')
  AND timestamp < toDateTime('{{ window.until }} 00:00:00')
FORMAT JSON
