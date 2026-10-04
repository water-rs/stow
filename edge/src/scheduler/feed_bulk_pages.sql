-- seed_feed_bulk's retained delivered pages: `?1`/`?2` bound the
-- chunk, the last three `?`s are hist_hours — the row count pages spread across so a
-- 1M-scale seed still distributes over the header set. applied=1:
-- history the delivery scan must skip, not apply.
WITH RECURSIVE seq(n) AS (
    SELECT ? UNION ALL SELECT n + 1 FROM seq WHERE n < ?
)
INSERT OR IGNORE INTO demand_feed_pages
    (hour, generation, page_no, entry_count, page_hash, chain_hash,
     payload, applied)
SELECT strftime('%Y-%m-%dT%H', '2018-01-01 00:00',
                '+' || ((n - 1) % ? + 1) || ' hours'),
       (n - 1) % ? + 1, (n - 1) / ?, 4,
       printf('%064x', n), printf('%064x', n + 1), '[]', 1 FROM seq
