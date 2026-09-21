-- Install-days over the last 7 days, from the `stow_events` dataset.
-- index1 is the daily-salted install hash: it changes every day, so
-- distinct values over 7 days count install-days, and the reader divides
-- by 7 for the daily average. `count(DISTINCT ...)` is the only distinct
-- aggregate the Analytics Engine SQL API supports (no `uniq`/`uniqIf`),
-- which is why the window is a WHERE clause rather than a condition.
SELECT
    count(DISTINCT index1) AS install_days_7d
FROM stow_events
WHERE blob1 = 'hit' AND timestamp >= NOW() - INTERVAL '7' DAY
FORMAT JSON
