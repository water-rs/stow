-- Builds, cache hits, local compiles and CPU milliseconds saved, from
-- the `build` points of the `stow_events` dataset: the installs' CLIs
-- report each day's counters in one point (stow#889), doubles 2–5 the
-- reported cpu_millis_saved, hits, misses and builds. Each point's
-- stored weight is its sampling interval: SUM(_sample_interval *
-- doubleN) is the exact count under today's unsampled writes and stays
-- correct if the dataset ever samples. The outer WHERE bounds the scan
-- at the largest window any condition uses (30 days).
SELECT
    sumIf(_sample_interval * double5, blob1 = 'build' AND timestamp >= NOW() - INTERVAL '1' DAY) AS builds_24h,
    sumIf(_sample_interval * double3, blob1 = 'build' AND timestamp >= NOW() - INTERVAL '1' DAY) AS hits_24h,
    sumIf(_sample_interval * double4, blob1 = 'build' AND timestamp >= NOW() - INTERVAL '1' DAY) AS misses_24h,
    sumIf(_sample_interval * double2, blob1 = 'build' AND timestamp >= NOW() - INTERVAL '30' DAY) AS cpu_millis_saved_30d
FROM stow_events
WHERE timestamp >= NOW() - INTERVAL '30' DAY
FORMAT JSON
