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

A second dataset, `stow_events`, holds two point kinds:

- **`build` — one point per accepted daily build report** (unsampled).
  Each install's CLI sends at most one report per UTC day to
  `POST /api/v1/build-report` — four counters with the deltas since the
  last report: builds run, artifacts served from the cache, artifacts
  compiled locally, and `cpu_millis_saved` (the recorded compile time
  of the served artifacts, summed). No crate names, digests, dependency
  graph or lockfile is ever in the body.
- **`hit` — one point per uncached bundle fetch** (unsampled). The
  digest-addressed byte path knows only the bundle digest it served, so
  the point carries that digest and nothing else about the artifact;
  `stow-admin` resolves digests to crate identities offline from the
  public signed index. Most cache hits never reach the Worker — the
  platform cache answers them — so this point counts the cold path
  only and is used solely for ranking, never as a total.

Every `stow_events` point carries, as its index and dimension blobs:

- **Index:** the install hash — the day's UTC date and a random per-day
  salt hashed with the request's IP address, so an install counts once
  per day and cannot be joined across days.
- **Blobs:** the point kind (`hit`/`build`), the rustc version on hit
  points, a size bucket on hit points, the CLI version and operating
  system parsed from the `stow-cli/<version> (<os>)` user agent, the
  surface the request came through, the bundle digest on hit points,
  Cloudflare's country code (`CF-IPCountry`; the IP itself is never
  stored), and `ci` or `local` from the `x-stow-ci` header the CLI
  sends when `CI` is set.
- **Doubles:** `hit` points store `1.0`, `0.0`, the bundle's byte size;
  `build` points store `1.0`, `cpu_millis_saved`, hits, misses and
  builds.

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
Published figures are suppressed when they could single out a user:
the daily install average requires at least **20** distinct installs,
and every leaderboard bucket — digest, rustc, CLI version, operating
system, country and CI/local — is published only when at least **20**
distinct install-days landed in it, however many hits it counted.

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