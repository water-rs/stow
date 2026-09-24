-- `stow-admin preheat missed`: rank the most-missed crate identities per
-- CI target by sampled miss volume. The Analytics Engine SQL API takes
-- no bound parameters, so the per-target limit, the day window, and the
-- target list are substituted into the `__…__` markers at runtime — the
-- two integers are unsigned and every target literal is validated
-- against `stow_types::api::CI_TARGET_TRIPLES` before formatting, so
-- nothing attacker-controlled reaches the query text.
--
-- Blob layout (edge/src/miss_logger.rs): blob1 event, blob2 crate_name,
-- blob3 version, blob4 features_json, blob5 target, blob6 rustc_version,
-- blob7 artifact kind, blob8 lookup path, blob9 depends_on_json. Only
-- `semantic` and `graph` points carry a version, so `exact` misses are
-- excluded.
--
-- The inner query reduces raw points to per-(target, identity) miss
-- counts; the outer `topKWeighted` keeps the top-N per target
-- (Analytics Engine supports neither `LIMIT n BY` nor `UNION`, so a
-- per-group limit has to be an aggregate). Each `top_missed` element is
-- `crate;version;features_json;depends_on_json;misses` — `;` appears in
-- none of the fields: crate names, versions, Cargo feature names,
-- target triples, and rustc versions are all identifier-shaped, and the
-- JSON fields serialize only those atoms plus punctuation.
SELECT
    target,
    topKWeighted(__LIMIT__)(
        format('{};{};{};{};{}', crate_name, version, features_json, depends_on_json, misses),
        misses
    ) AS top_missed
FROM (
    SELECT
        blob5 AS target,
        blob2 AS crate_name,
        blob3 AS version,
        blob4 AS features_json,
        any(blob9) AS depends_on_json,
        SUM(_sample_interval) AS misses
    FROM stow_cache_misses
    WHERE
        blob1 = 'miss'
        AND blob8 IN ('semantic', 'graph')
        AND blob2 <> ''
        AND blob3 <> ''
        AND blob5 IN (__TARGETS__)
        AND timestamp >= NOW() - INTERVAL '__SINCE_DAYS__' DAY
    GROUP BY
        target,
        crate_name,
        version,
        features_json
)
GROUP BY target
ORDER BY target
FORMAT JSON
