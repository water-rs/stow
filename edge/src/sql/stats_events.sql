-- Totals for the public stats surface, from the `stow_events` dataset.
-- Hit rows store the sample weight in double1, so SUM(double1) is the
-- scaled estimate; double2 is compile_millis. index1 is the daily-salted
-- install hash: it changes every day, so distinct values over 7 days count
-- install-days, and the reader divides by 7 for the daily average.
SELECT
    sumIf(double1, blob1 = 'hit' AND timestamp >= NOW() - INTERVAL '1' DAY) AS hits_24h,
    uniqIf(index1, blob1 = 'hit' AND timestamp >= NOW() - INTERVAL '7' DAY) AS install_days_7d,
    sumIf(double1 * double2, blob1 = 'hit' AND timestamp >= NOW() - INTERVAL '30' DAY) AS hit_compile_millis_30d
FROM stow_events
FORMAT JSON
