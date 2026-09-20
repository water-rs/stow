-- Hits per compilation target over the last 30 days. blob2 is the
-- target triple, double1 the sample weight.
SELECT
    blob2 AS name,
    sum(double1) AS hits
FROM stow_events
WHERE blob1 = 'hit' AND timestamp >= NOW() - INTERVAL '30' DAY
GROUP BY name
ORDER BY hits DESC
LIMIT 10
FORMAT JSON
