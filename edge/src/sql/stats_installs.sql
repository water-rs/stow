-- Unique install events in the last 24 hours. index1 = toYYYYMMDD(timestamp)
-- salts the time_trunc_group key per day, so distinct counter values of
-- (day, counter) survive the engine's own aggregation — the count is
-- unique installs per day, deduplicated across retries and page views.
--
-- This is a sample-observed figure, not an additive estimate: privacy
-- suppression drops some installs entirely and their counter values
-- never reach the dataset, so no `_sample_interval` rescaling recovers
-- them. `count(DISTINCT index1)` reports exactly what was observed —
-- we do not fabricate an unbiased estimate from the observed set.
SELECT
    count(DISTINCT index1) AS installs_24h
FROM stow_events
WHERE blob1 = 'install' AND timestamp >= NOW() - INTERVAL '1' DAY
FORMAT JSON
