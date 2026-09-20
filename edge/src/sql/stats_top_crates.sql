-- Most-served crates over the last 30 days. blob4 is crate_name,
-- double1 the sample weight.
SELECT
    blob4 AS name,
    sum(double1) AS hits
FROM stow_events
WHERE blob1 = 'hit' AND timestamp >= NOW() - INTERVAL '30' DAY
GROUP BY name
ORDER BY hits DESC
LIMIT 10
FORMAT JSON
