-- seed_feed_bulk's historical delivered headers: the two `?`s bound the
-- recursive row range this chunk writes — strftime rolls the hour
-- from 2018-01-01 so the PK stays ordered and `INSERT OR IGNORE`
-- makes a repeat re-arm a dedupe pass.
WITH RECURSIVE seq(n) AS (
    SELECT ? UNION ALL SELECT n + 1 FROM seq WHERE n < ?
)
INSERT OR IGNORE INTO demand_feed_hours
    (hour, generation, state, staged_pages, staged_entries, applied_pages,
     page_count, entry_count)
SELECT strftime('%Y-%m-%dT%H', '2018-01-01 00:00', '+' || n || ' hours'),
       n, 'delivered', 4, 16, 4, 4, 16 FROM seq
