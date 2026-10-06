-- Cache misses in the last 24 hours, from the `stow_cache_misses`
-- dataset. Miss points write double1 = 1.0 unsampled, so
-- SUM(_sample_interval * double1) is `count()` under today's write
-- pattern — and stays correct if the dataset ever samples.
SELECT
    sum(_sample_interval * double1) AS misses_24h
FROM stow_cache_misses
WHERE blob1 = 'miss' AND timestamp >= NOW() - INTERVAL '1' DAY
FORMAT JSON
