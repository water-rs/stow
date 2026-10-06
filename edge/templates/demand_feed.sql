-- The hourly demand feed's closed-hour query (stow#523): the miss
-- volume the scheduler's unbuilt closure ranks demand from. One
-- query per closed hour — `hour` is the validated `DemandFeedHour`
-- (YYYY-MM-DD HH UTC) the askama template substitutes (the SQL API
-- takes no bound parameters; the literal is digits/dash/space only
-- and the range is checked before formatting). The window arithmetic
-- stays in the query so no caller-side date math exists.
--
-- Blob layout (edge/src/miss_logger.rs): blob1 event, blob2 crate_name,
-- blob3 version, blob4 features_json, blob5 target, blob6 rustc_version.
-- Only `semantic` and `graph` points carry a version (top_missed.sql's
-- path filter); `exact` misses carry none and are excluded the same
-- way. Miss writes honor the `STOW_NO_ANALYTICS` consent at write
-- time — points an opted-out caller never wrote cannot appear, and
-- no rescaling recovers them.
--
-- `sum(_sample_interval * double1)` is the documented additive
-- estimate: `_sample_interval` is the engine's per-row sampling
-- interval and `double1` the stored caller weight — 1.0 today, so the
-- sum is exact under current writes and stays correct if the dataset
-- ever samples. Sampling produces estimates over the returned
-- identities; it cannot reconstruct identities the sample suppressed.
--
-- Deterministic full ordering over the identity columns with
-- `LIMIT ALL`, so a page boundary the feed's materializer draws is a
-- property of the feed, not the engine, and one replayed document
-- yields the same pages.
SELECT
    blob2 AS crate_name,
    blob3 AS version,
    blob4 AS features_json,
    blob5 AS target,
    blob6 AS rustc_version,
    sum(_sample_interval * double1) AS demand
FROM stow_cache_misses
WHERE blob1 = 'miss'
    AND blob8 IN ('semantic', 'graph')
    AND blob2 <> ''
    AND blob3 <> ''
    AND timestamp >= toDateTime('{{ hour.sql_literal() }}:00:00')
    AND timestamp < toDateTime('{{ hour.sql_literal() }}:00:00') + INTERVAL '1' HOUR
GROUP BY crate_name, version, features_json, target, rustc_version
ORDER BY crate_name, version, features_json, target, rustc_version
LIMIT ALL
FORMAT JSON
