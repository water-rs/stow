# Public request API

`POST /api/v1/requests` is the submission path behind the request form on
`stow.waterui.dev`: a human asks for one crate (and its dependency
closure) to be prebuilt into the public cache for every CI target the
build fleet covers. Admission is a Cloudflare Turnstile token — the
miss path's proof-of-work admission on `/api/v1/enqueue` is unchanged
and unrelated. Accepted work enters the scheduler's human lane ahead of
queued misses; see
[`ARCHITECTURE.md`](ARCHITECTURE.md#human-request-lane) for the lane
semantics.

All wire types live in `stow_types::api`; names below are the Rust
fields serialized by serde.

## `POST /api/v1/requests`

Body: `CrateRequest`.

| Field | Type | Notes |
|---|---|---|
| `crate_name` | `CrateName` | Name as published on crates.io |
| `version` | `CrateVersion?` | Exact version; when absent the edge resolves the newest non-prerelease, non-yanked release |
| `features_json` | `FeaturesJson` | Canonical sorted feature list; `[]` means `--no-default-features` with nothing added — the `default` feature must be listed explicitly to keep the crate's default set |
| `turnstile_token` | `string` | Token minted by the invisible Turnstile widget on the request page; its siteverify `hostname` must equal the deployment's `TURNSTILE_HOSTNAME` |

```json
{
  "crate_name": "serde_json",
  "version": null,
  "features_json": "[\"preserve_order\"]",
  "turnstile_token": "0.aBCDef…"
}
```

Response `200`: `CrateRequestStatus` — the request record as it stands
at the moment of admission. The edge resolves nothing itself: a request
the scheduler accepts is dispatched to `resolve-request.yml` on GitHub
Actions, which resolves the closure and submits the tasks; `status`
walks `accepted` → `resolving` → `enqueued` (or `failed`) over the
record's lifetime.

| Field | Type | Notes |
|---|---|---|
| `request_id` | `string` | Stable id `req-<crate>-<version>-<features-hash>-<rustc>`; resubmitting an identical request re-answers the live record |
| `crate_name`, `version`, `features_json`, `rustc_version` | identity newtypes | The request's identity — version and rustc resolved to concrete values at admission |
| `status` | `CrateRequestPhase` | `accepted` \| `resolving` \| `enqueued` \| `failed` |
| `targets` | `CrateRequestTarget[]` | Per-target outcome, `CI_TARGET_TRIPLES` order (`aarch64-apple-darwin`, `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `aarch64-linux-android`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, `wasm32-unknown-unknown`); empty until `status` reaches `enqueued` |
| `error` | `string?` | Why the record failed; `null` otherwise |
| `github_run_id`, `github_run_url` | `string?` | The Actions resolve run once it starts (`resolving` onward); `null` before |

```json
{
  "request_id": "req-serde_json-1.0.149-4f0a1b2c-1_98_1",
  "crate_name": "serde_json",
  "version": "1.0.149",
  "features_json": "[\"preserve_order\"]",
  "rustc_version": "1.98.1",
  "status": "accepted",
  "targets": [],
  "error": null,
  "github_run_id": null,
  "github_run_url": null
}
```

`CrateRequestTarget` (populated at `enqueued`; states then keep moving
on each read until the target is cached):

| Field | Type | Notes |
|---|---|---|
| `target` | `TargetTriple` | The CI target |
| `state` | `CrateRequestState` | `cached` \| `queued` \| `already_queued` \| `building` \| `closure_queued` |
| `task_id` | `string?` | Scheduler task id for the root crate on this target; absent when `state` is `cached` or `closure_queued` |
| `human_lane_position` | `u32?` | 1-based position among pending human-lane tasks; `null` unless still pending there |

`closure_queued` means the requested crate publishes no library target
(a bin-only package): the cache has no identity to publish it under, so
the crate itself is never a task and what enqueued was its dependency
closure — exactly what `cargo install <crate>` would otherwise compile.

A record ends `failed` when the resolve job cannot complete it — the
closure exceeding `STOW_HUMAN_MAX_CLOSURE` crates (150 in the production
manifest) is one such failure; `error` names the reason.

Errors:

- `400` — a malformed feature name.
- `403` — Turnstile rejected the token. The body is
  `{"error":"turnstile rejected","error-codes":[...]}`: siteverify's own
  `error-codes` when the challenge failed, `["siteverify-unavailable"]`
  when siteverify itself could not be reached or read, and
  `["hostname-mismatch"]` when the token's siteverify `hostname` does not
  equal the deployment's `TURNSTILE_HOSTNAME` — tokens are pinned to the
  site that minted them.
- `404` — the crate (or the requested exact version) is not published on
  crates.io.
- `429` — the human lane has spent its `STOW_HUMAN_DAILY_TASK_BUDGET` for
  today (2000 tasks in production); `Retry-After` counts the seconds to
  00:00 UTC, when the counter resets.

## `GET /api/v1/requests/{request_id}`

`{request_id}` is the `request_id` returned above. Response `200`: the
same `CrateRequestStatus` shape, live — `status` advances as the resolve
run reports in (`accepted` → `resolving`) and as its outcome lands
(`enqueued` with `targets` populated, or `failed` with `error`). An
`enqueued` record's targets are re-read against the queue on every
request, so `state`/`human_lane_position` stay truthful until every
target is `cached`.

```json
{
  "request_id": "req-serde_json-1.0.149-4f0a1b2c-1_98_1",
  "crate_name": "serde_json",
  "version": "1.0.149",
  "features_json": "[\"preserve_order\"]",
  "rustc_version": "1.98.1",
  "status": "enqueued",
  "targets": [
    { "target": "aarch64-apple-darwin", "state": "queued", "task_id": "serde_json-1.0.149-4f0a…-aarch64_apple_darwin-1.98.1-d1c4f9…", "human_lane_position": 1 },
    { "target": "aarch64-apple-ios", "state": "queued", "task_id": "serde_json-1.0.149-4f0a…-aarch64_apple_ios-1.98.1-d3a8e2b…", "human_lane_position": 2 },
    { "target": "aarch64-apple-ios-sim", "state": "building", "task_id": "serde_json-1.0.149-4f0a…-aarch64_apple_ios_sim-1.98.1-d5f2c71…", "human_lane_position": null },
    { "target": "aarch64-linux-android", "state": "already_queued", "task_id": "serde_json-1.0.149-4f0a…-aarch64_linux_android-1.98.1-d77b0e4…", "human_lane_position": 3 },
    { "target": "x86_64-unknown-linux-gnu", "state": "queued", "task_id": "serde_json-1.0.149-4f0a…-x86_64_unknown_linux_gnu-1.98.1-da9d3f6…", "human_lane_position": 4 },
    { "target": "aarch64-unknown-linux-gnu", "state": "queued", "task_id": "serde_json-1.0.149-4f0a…-aarch64_unknown_linux_gnu-1.98.1-d4e6b21…", "human_lane_position": 5 },
    { "target": "x86_64-pc-windows-msvc", "state": "cached", "task_id": null, "human_lane_position": null },
    { "target": "aarch64-pc-windows-msvc", "state": "queued", "task_id": "serde_json-1.0.149-4f0a…-aarch64_pc_windows_msvc-1.98.1-d8f0a53…", "human_lane_position": 6 },
    { "target": "wasm32-unknown-unknown", "state": "queued", "task_id": "serde_json-1.0.149-4f0a…-wasm32_unknown_unknown-1.98.1-d2b9c6d…", "human_lane_position": 7 }
  ],
  "error": null,
  "github_run_id": "123456789",
  "github_run_url": "https://github.com/water-rs/stow/actions/runs/123456789"
}
```

`404` when the id is not a live request record.

## Crate catalog

Three read-only lookups back the request form's crate field, version
picker, and feature checkboxes. They are a thin, cached proxy over
crates.io: the browser never talks to crates.io directly, so its CORS
and user-agent rules do not apply to every visitor, and the version and
feature answers come out of the same TTL-bounded D1 caches the
dependency resolver fills — a catalog lookup and a later graph expansion
of the same version share one round trip.

Every response carries `Cache-Control: public, max-age=…` (300 s for
search, 600 s for versions and features).

### `GET /api/v1/crates/search`

| Query | Type | Notes |
|---|---|---|
| `q` | `string` | Search text; at least 2 characters after trimming |
| `limit` | `u32?` | Default 10, clamped into `1..=25` |

Response `200`: `CrateSearchResponse`, most relevant first.

```json
{
  "crates": [
    {
      "crate_name": "serde",
      "description": "A generic serialization/deserialization framework",
      "max_version": "1.0.229",
      "downloads": 1410307353
    }
  ]
}
```

`max_version` is the newest non-prerelease release, falling back to the
newest prerelease for a crate that has never published a stable one.

`400` when `q` is shorter than two characters.

### `GET /api/v1/crates/{crate_name}/versions`

Response `200`: `CrateVersionsResponse` — every published, non-yanked
version, newest first.

```json
{ "versions": ["1.0.229", "1.0.228", "1.0.227"] }
```

`400` when `{crate_name}` is not a legal crate name; `404` when
crates.io does not publish it.

### `GET /api/v1/crates/{crate_name}/versions/{version}/features`

Response `200`: `CrateFeaturesResponse` — every feature a request may
select on that version, `default` first and the rest alphabetical.

```json
{
  "features": [
    { "name": "default", "implies": ["std"], "default": true },
    { "name": "derive", "implies": ["serde_derive"], "default": false },
    { "name": "std", "implies": [], "default": true }
  ]
}
```

The list is the crate's declared `[features]` keys plus the implicit
feature cargo grants each optional dependency — minus the optional
dependencies a declared feature reaches through `dep:<name>`, which
hides the implicit one. `implies` is empty for such an implicit feature.
`default` marks the features the `default` set enables, directly or
transitively, and is what lets a client show them as already on.

A `features_json` that omits `default` is what makes the build
`--no-default-features`; the features it implies need not be listed —
cargo derives the enabled closure when it builds.

`400` when `{crate_name}` is not a legal crate name or `{version}` is
not semver; `404` when crates.io does not publish the crate.

## Index slices

The landing page's "is this crate cached?" lookup reads the same signed
index slice the CLI's resolver uses — the zstd JSON `ArtifactIndex`
published per `(target, rustc_version)` as the OCI tag
`index.<target>.<rustc>` on `ghcr.io/water-rs/stow-cache`. A browser
cannot run GHCR's anonymous bearer exchange or reach ghcr.io
cross-origin, so the worker serves the slice from its own origin in two
steps: a short-lived tag→digest pointer, then the immutable
digest-addressed bytes.

### `GET /api/v1/index/{target}/{rustc_version}`

Resolves the `index.<target>.<rustc_version>` tag to the digest the
layer blob currently has. `{rustc_version}` may be the literal `stable`,
which resolves through the scheduler's cached channel manifest.

Response `200`: `IndexSlicePointer`, `Cache-Control: public, max-age=60`
— the tag moves at every index publish, so the pointer is short-lived.

```json
{
  "target": "x86_64-unknown-linux-gnu",
  "rustc_version": "1.98.1",
  "digest": "sha256:0123…",
  "size": 143872
}
```

`400` for a malformed target or rustc version; `404` when no index slice
is published for the pair; `502` when GHCR is rate-limiting or down.

### `GET /api/v1/index/{target}/{rustc_version}/{digest}`

The slice blob itself, fetched from GHCR and cached at the edge by
Workers Cache on the digest-addressed URL. `{digest}` must be `sha256:`
plus 64 lowercase hex digits — anything else is `400`. On a cache miss
the digest must also name the layer the pair's index tag currently
points at, or the route answers `404`; an already-cached older digest
is still served.

Response `200`: the slice bytes with `Content-Type: application/json`,
`Cache-Control: public, max-age=31536000, immutable` (the digest
content-addresses the body) and `Vary: Accept-Encoding`; a hit may
answer from Workers Cache with the Worker never running — billed as a
request, but spending no CPU or subrequests. The
`Content-Encoding` negotiates on the request's `Accept-Encoding`:
clients naming `zstd` get the published blob byte-for-byte
(`Content-Encoding: zstd`); anything else — an absent token, a `q=0`
refusal — gets a gzip transcode the platform caches under its own
`Vary` variant (`Content-Encoding: gzip`).

## `GET /requests/{task_id}`

The same state as `GET /api/v1/requests/{task_id}`, rendered as a page
for a person: the request form's result table links here. The page
refreshes itself every 20 seconds while the task is pending, dispatched,
or running, and stops once it completes or fails. `404` renders a page
saying the scheduler does not know the id.

## `GET /api/v1/stats`

Response `200`: `UsageStats` — the anonymous usage aggregates the
`/stats` page renders. Hit counts are scaled back up from the 1/10
sample; `daily_active_installs_7d` is `null` below an average of 20
distinct daily-salted install hashes per day.

| Field | Type | Notes |
|---|---|---|
| `daily_active_installs_7d` | `u64?` | Average distinct installs served per day over 7 days (sampled lower bound) |
| `hits_24h` | `u64` | Cache hits served in 24 hours (sample-scaled) |
| `misses_24h` | `u64` | Cache misses in 24 hours (unsampled) |
| `hit_rate_24h` | `f64` | `hits_24h / (hits_24h + misses_24h)` |
| `cpu_hours_saved_30d` | `f64` | Recorded compile time of served artifacts, sample-scaled, in hours |
| `top_crates_30d` | `UsageStatEntry[]` | 10 most-served crates, `{name, hits}` |
| `targets_30d` | `UsageStatEntry[]` | Hits per compilation target |
| `cli_versions_30d` | `UsageStatEntry[]` | Hits per `stow-cli` version |

```json
{
  "daily_active_installs_7d": 1320,
  "hits_24h": 48110,
  "misses_24h": 5210,
  "hit_rate_24h": 0.902,
  "cpu_hours_saved_30d": 118.4,
  "top_crates_30d": [{ "name": "serde", "hits": 12940 }],
  "targets_30d": [{ "name": "x86_64-unknown-linux-gnu", "hits": 30210 }],
  "cli_versions_30d": [{ "name": "0.1.0", "hits": 45100 }]
}
```


## `GET /stats`

The `GET /api/v1/stats` numbers rendered as a page for a person, linked
from the landing page's nav. Both stats routes are anonymous and the
JSON is Workers-Cached for one hour. The collected fields, sampling,
retention, and opt-out are documented in [`PRIVACY.md`](../PRIVACY.md).
