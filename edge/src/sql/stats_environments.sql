-- Reported activity split between CI and local builds over the last
-- 30 days, from the `build` points of the `stow_events` dataset:
-- blob12 is `ci` when the CLI sent `x-stow-ci: 1`, `local` otherwise.
-- The scaled estimate sums each point's sampling interval times its
-- stored caller weight (`_sample_interval * double1`) — exact under
-- today's unsampled writes.
SELECT
    blob12 AS name,
    sum(_sample_interval * double1) AS hits,
    count(DISTINCT index1) AS install_days
FROM stow_events
WHERE blob1 = 'build' AND blob12 != '' AND timestamp >= NOW() - INTERVAL '30' DAY
GROUP BY name
ORDER BY hits DESC
LIMIT 10
FORMAT JSON
