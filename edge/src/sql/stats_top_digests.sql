-- Most-served bundle digests over the last 30 days, from the `hit`
-- points of the `stow_events` dataset: blob10 is the bundle digest the
-- digest-addressed byte path served (stow#889). The figure is an
-- edge-observed undercount — the platform cache answers most fetches
-- before the Worker runs — used for ranking only; stow-admin resolves
-- each digest to a crate identity from the public signed index. The
-- scaled estimate sums each point's sampling interval times its stored
-- caller weight (`_sample_interval * double1`) — exact under today's
-- unsampled writes.
SELECT
    blob10 AS name,
    sum(_sample_interval * double1) AS hits,
    count(DISTINCT index1) AS install_days
FROM stow_events
WHERE blob1 = 'hit' AND blob10 != '' AND timestamp >= NOW() - INTERVAL '30' DAY
GROUP BY name
ORDER BY hits DESC
LIMIT 10
FORMAT JSON
