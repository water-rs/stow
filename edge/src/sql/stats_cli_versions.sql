-- Hits per CLI version over the last 30 days. blob7 is the version
-- parsed from the `stow-cli/<version> (<os>)` user agent; requests that
-- sent none carry the empty string and are excluded. double1 is the
-- sample weight.
SELECT
    blob7 AS name,
    sum(double1) AS hits
FROM stow_events
WHERE blob1 = 'hit' AND blob7 != '' AND timestamp >= NOW() - INTERVAL '30' DAY
GROUP BY name
ORDER BY hits DESC
LIMIT 10
FORMAT JSON
