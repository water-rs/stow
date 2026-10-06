-- Hit totals for the public stats surface, from the `stow_events`
-- dataset. The additive scaled estimate is SUM(_sample_interval *
-- double1): `_sample_interval` is the engine's recorded sampling
-- interval per point and `double1` the caller's stored weight, so
-- unsampled points (`_sample_interval` = 1) still count their full
-- weight. double2 is compile_millis. The install count lives in
-- stats_installs.sql: the Analytics Engine SQL API has no conditional
-- distinct count, so it needs its own WHERE clause. The outer WHERE
-- bounds the scan at the largest window any condition uses (30 days).
SELECT
    sumIf(_sample_interval * double1, blob1 = 'hit' AND timestamp >= NOW() - INTERVAL '1' DAY) AS hits_24h,
    sumIf(_sample_interval * double1 * double2, blob1 = 'hit' AND timestamp >= NOW() - INTERVAL '30' DAY) AS hit_compile_millis_30d
FROM stow_events
WHERE timestamp >= NOW() - INTERVAL '30' DAY
FORMAT JSON
