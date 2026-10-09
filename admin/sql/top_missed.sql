-- `stow-admin preheat missed`: rank the most-missed task ids per CI
-- target by sampled miss volume, for promote-by-id submission
-- (stow#588). The Analytics Engine SQL API takes no bound parameters,
-- so the per-target limit, the day window, and the target list are
-- substituted into the `__…__` markers at runtime — the two integers
-- are unsigned and every target literal is validated against
-- `stow_types::api::CI_TARGET_TRIPLES` before formatting, so nothing
-- attacker-controlled reaches the query text.
--
-- Blob layout (edge/src/miss_logger.rs): blob1 event, blob2 crate_name,
-- blob3 version, blob4 features_json, blob5 target, blob6 rustc_version,
-- blob7 artifact kind, blob8 lookup path, blob9 depends_on_json,
-- blob10 dependency_identity, blob11 host_side, blob12 task_id.
-- Historical points written before the task-id blob existed carry an
-- empty blob12 — excluded here, never promoted under a guessed id.
-- The task id already folds the toolchain, side, and dependency context
-- into itself, so it is the whole grouping key.
--
-- The inner query reduces raw points to per-(target, task-id) miss
-- counts; the outer `topKWeighted` keeps the top-N per target
-- (Analytics Engine supports neither `LIMIT n BY` nor `UNION`, so a
-- per-group limit has to be an aggregate). Each `top_missed` element is
-- `task_id;misses` — `;` appears in neither field: task ids are
-- identifier-shaped with `-d<digest>` separators and misses is an
-- integer.
SELECT
    target,
    topKWeighted(__LIMIT__)(
        format('{};{}', task_id, misses),
        misses
    ) AS top_missed
FROM (
    SELECT
        blob5 AS target,
        blob12 AS task_id,
        SUM(_sample_interval) AS misses
    FROM stow_cache_misses
    WHERE
        blob1 = 'miss'
        AND blob8 = 'graph'
        AND blob6 = '__RUSTC_VERSION__'
        AND blob12 <> ''
        AND blob5 IN (__TARGETS__)
        AND timestamp >= NOW() - INTERVAL '__SINCE_DAYS__' DAY
    GROUP BY
        target,
        task_id
)
GROUP BY target
FORMAT JSON
