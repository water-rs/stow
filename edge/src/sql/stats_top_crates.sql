-- Most-served crates over the last 30 days. blob4 is crate_name. The
-- scaled estimate sums each point's sampling interval times its
-- stored caller weight: `_sample_interval` for unsampled writes is 1,
-- so the sum is exact under today's writes and stays correct if the
-- dataset ever samples.
SELECT
    blob4 AS name,
    sum(_sample_interval * double1) AS hits
FROM stow_events
WHERE blob1 = 'hit' AND timestamp >= NOW() - INTERVAL '30' DAY
GROUP BY name
ORDER BY hits DESC
LIMIT 10
FORMAT JSON
