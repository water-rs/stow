-- The re-arm's bounded reset of the staging hour's obsolete tail:
-- `?` is staged_pages — obsolete rows number the 256 above it, under
-- the fixed generation 7 the bulk seed assigns. `OR IGNORE` +
-- the delete that precedes make a repeat re-arm exact.
WITH RECURSIVE seq(n) AS (
    SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n <= 256
)
INSERT OR IGNORE INTO demand_feed_pages
    (hour, generation, page_no, entry_count, page_hash, chain_hash,
     payload, applied)
SELECT '2022-01-01T00', 7, ? + n, 4,
       printf('%064x', ? + n + 100000), printf('%064x', ? + n + 100001),
       '[]', 0 FROM seq
