-- Hits per compilation target over the last 30 days. blob2 is the
-- target triple. The scaled estimate sums each point's sampling
-- interval times its stored caller weight (`_sample_interval *
-- double1`), which is the exact count for today's unsampled writes.
SELECT
    blob2 AS name,
    sum(_sample_interval * double1) AS hits
FROM stow_events
WHERE blob1 = 'hit' AND timestamp >= NOW() - INTERVAL '30' DAY
GROUP BY name
ORDER BY hits DESC
LIMIT 10
FORMAT JSON
