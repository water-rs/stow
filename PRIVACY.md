# Privacy

Stow collects a small set of anonymous, aggregate usage statistics so the
project can see what the cache does not cover. This document lists
exactly what is collected, what is never collected, how long it is
retained, and how to opt out.

## What is collected

Analytics are written server-side by the edge worker, from request fields
the CLI already sends, into one Cloudflare Analytics Engine dataset. No
client-side tracking, cookies, or telemetry SDKs are involved.

### `stow_cache_misses` — cache misses

One point per cache miss (unsampled), with:

- **Index:** the crate name.
- **Blobs:** `"miss"`, crate name, crate version, requested features JSON,
  compilation target triple, rustc version, an artifact-kind slot
  (written but currently always empty), the lookup path (always
  `graph`), and the missed node's dependency edges as JSON.
- **Doubles:** `1.0`.

A second dataset, `stow_events`, holds one point per sampled cache hit
from the era when the byte path resolved catalog rows and knew the
artifact's identity; the digest-addressed byte path carries no identity
and writes nothing, so that dataset only drains under retention.

## What is never collected

- IP addresses — never written to any dataset, log, or table.
- Dependency graphs beyond the uncovered nodes a miss admission names,
  lockfile contents, or lockfile hashes.
- Project names, workspace paths, or any file path.
- Machine identifiers, hostnames, or hardware fingerprints.
- Request counts attributable to any person or project.

## Retention

Raw Analytics Engine data points are retained for 90 days by Cloudflare.
Only the published aggregates on `/stats` survive beyond that window.

## Opting out

Set `STOW_NO_ANALYTICS=1` in the environment before running `stow`. The
CLI then sends `x-stow-no-analytics: 1` on every request, and the edge
worker writes no analytics point for that request. The opt-out is
enforced at every write site by a request-scoped consent extractor, not
by remembering to check a flag.

## Local statistics

`stow stats` is local-only: it reads counters the CLI keeps in its own
data directory and sends nothing.

## The website

The stow site uses cookieless Cloudflare Web Analytics, which collects
page views and referrers without cookies or client-side state.
