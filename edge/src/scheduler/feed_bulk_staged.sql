-- seed_feed_bulk's staging-hour page bulk on '2022-01-01T00' (gen 9):
-- `?1`/`?2` bound the chunk, the last `?` is staged_pages — rows at or below
-- it stage current-generation depth, the 256-row tail above it is the
-- obsolete generation 7 the retire index is measured against.
WITH RECURSIVE seq(n) AS (
    SELECT ? UNION ALL SELECT n + 1 FROM seq WHERE n < ?
)
INSERT OR IGNORE INTO demand_feed_pages
    (hour, generation, page_no, entry_count, page_hash, chain_hash,
     payload, applied)
SELECT '2022-01-01T00', CASE WHEN n <= ? THEN 9 ELSE 7 END,
       n, 4, printf('%064x', n + 100000), printf('%064x', n + 100001),
       '[]', 0 FROM seq
