-- Totals for the public stats surface, from the `stow_events` dataset.
-- Hit rows store the sample weight in double1, so SUM(double1) is the
-- scaled estimate; double2 is compile_millis on hits and cpu_millis on
-- `share` rows. index1 is the daily-salted install hash.
SELECT
    sumIf(double1, blob1 = 'hit' AND timestamp >= NOW() - INTERVAL '1' DAY) AS hits_24h,
    uniqIf(index1, blob1 = 'hit' AND timestamp >= NOW() - INTERVAL '7' DAY) AS active_installs_7d,
    sumIf(double1 * double2, blob1 = 'hit' AND timestamp >= NOW() - INTERVAL '30' DAY) AS hit_compile_millis_30d,
    sumIf(double2, blob1 = 'share' AND timestamp >= NOW() - INTERVAL '30' DAY) AS shared_cpu_millis_30d
FROM stow_events
FORMAT JSON
