-- Hit totals for the public stats surface, from the `stow_events`
-- dataset. Hit rows store the sample weight in double1, so SUM(double1)
-- is the scaled estimate; double2 is compile_millis. The install count
-- lives in stats_installs.sql: the Analytics Engine SQL API has no
-- conditional distinct count, so it needs its own WHERE clause.
SELECT
    sumIf(double1, blob1 = 'hit' AND timestamp >= NOW() - INTERVAL '1' DAY) AS hits_24h,
    sumIf(double1 * double2, blob1 = 'hit' AND timestamp >= NOW() - INTERVAL '30' DAY) AS hit_compile_millis_30d
FROM stow_events
FORMAT JSON
