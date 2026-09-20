# Privacy

Stow collects a small set of anonymous, aggregate usage statistics so the
project can answer questions like "how many builds were accelerated today"
and "how much CPU time did the cache save". This document lists exactly
what is collected, what is never collected, how long it is retained, and
how to opt out.

## What is collected

Analytics are written server-side by the edge worker, from request fields
the CLI already sends, into two Cloudflare Analytics Engine datasets. No
client-side tracking, cookies, or telemetry SDKs are involved.

### `stow_events` — cache hits and shared savings

One point per *sampled* cache hit (see "Sampling" below), with:

- **Index:** the daily-salted install hash (see below).
- **Blobs:** `"hit"`, compilation target triple, rustc version, crate
  name, crate version, bundle size bucket (`<1MB`, `1-10MB`, `10-100MB`,
  `>100MB`), CLI version, OS family, and the serving surface (`exact`,
  `semantic`, or `batch`).
- **Doubles:** the sample weight (`10.0`), the original compile time of
  the artifact in milliseconds, and the bundle size in bytes.

### `stow_cache_misses` — cache misses

One point per cache miss (unsampled), with:

- **Index:** the crate name.
- **Blobs:** `"miss"`, crate name, crate version, requested features JSON,
  compilation target triple, rustc version, artifact kind, and the lookup
  path (`exact`, `semantic`, or `graph`).
- **Doubles:** `1.0`.

## What is never collected

- IP addresses — the connecting IP is hashed in-worker and dropped; it is
  never written to any dataset, log, or table.
- Dependency graphs, lockfile contents, or lockfile hashes.
- Project names, workspace paths, or any file path.
- Machine identifiers, hostnames, or hardware fingerprints.
- Request counts attributable to any person or project.

## The install hash

"Active installs per day" is measured with an index of
`hex(HMAC-SHA256(daily_secret, client_ip))[..16]`, where
`daily_secret = HMAC-SHA256(STOW_STATS_SALT_SECRET, YYYY-MM-DD)` for the
current UTC day. The salt secret lives in the worker, the derived daily
key is never stored, and the IP never leaves the hash. Because the salt
changes every day, the same install produces a different index tomorrow —
the hash counts distinct installs within a day and cannot be joined
across days or linked back to any user.

## Sampling

Hit points are written with probability 1/10 and carry a sample weight of
`10.0` in their first double; queries multiply by the weight to recover
estimated totals. Miss points are unsampled. Sampling keeps Analytics
Engine write volume proportional to the insight, not to traffic.

## Retention

Raw Analytics Engine data points are retained for 90 days by Cloudflare.
Only the published aggregates on `/stats` survive beyond that window.

## Opting out

Set `STOW_NO_ANALYTICS=1` in the environment before running `stow`. The
CLI then sends `x-stow-no-analytics: 1` on every request, and the edge
worker writes no analytics point and computes no install hash for that
request. The opt-out is enforced at every write site by a request-scoped
consent extractor, not by remembering to check a flag.

## Local statistics

`stow stats` is local-only: it reads counters the CLI keeps in its own
data directory and sends nothing.

## The website

The stow site uses cookieless Cloudflare Web Analytics, which collects
page views and referrers without cookies or client-side state.
