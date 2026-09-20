-- Cache misses in the last 24 hours, from the `stow_cache_misses`
-- dataset. Miss points are unsampled — every point counts once.
SELECT
    count() AS misses_24h
FROM stow_cache_misses
WHERE blob1 = 'miss' AND timestamp >= NOW() - INTERVAL '1' DAY
FORMAT JSON
