-- seed_stale_feed_pages: the `?`s are count, hour, generation —
-- obsolete payloads under a staging hour, retirable debris for the
-- begin-rotation and cleanup drives. Direct unmetered INSERT: stale
-- generations retire unseen, so hashes/payloads are never real.
WITH RECURSIVE seq(n) AS (
    SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?
)
INSERT INTO demand_feed_pages
    (hour, generation, page_no, entry_count, page_hash, chain_hash,
     payload, applied)
SELECT ?, ?, n, 4, printf('%064x', n), printf('%064x', n + 1),
       '[]', 0 FROM seq
