-- Hits per rustc version over the last 30 days, from the `hit` points
-- of the `stow_events` dataset: blob3 is the rustc of the bundle the
-- digest-addressed byte path served (stow#889). Edge-observed and so
-- an undercount, used for share ranking only. The scaled estimate sums
-- each point's sampling interval times its stored caller weight
-- (`_sample_interval * double1`) — exact under today's unsampled
-- writes.
SELECT
    blob3 AS name,
    sum(_sample_interval * double1) AS hits,
    count(DISTINCT index1) AS install_days
FROM stow_events
WHERE blob1 = 'hit' AND blob3 != '' AND timestamp >= NOW() - INTERVAL '30' DAY
GROUP BY name
ORDER BY hits DESC
LIMIT 10
FORMAT JSON
