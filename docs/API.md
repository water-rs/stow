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
| `features_json` | `FeaturesJson` | Canonical sorted feature list; `[]` means the crate's `default` feature set |
| `turnstile_token` | `string` | Token minted by the invisible Turnstile widget on the request page |

```json
{
  "crate_name": "serde_json",
  "version": null,
  "features_json": ["preserve_order"],
  "turnstile_token": "0.aBCDef…"
}
```

Response `200`: `CrateRequestOutcome` — the resolved version, the stable
rustc the tasks target, and one `CrateRequestTarget` per entry of
`CI_TARGET_TRIPLES` (`x86_64-unknown-linux-gnu`,
`aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, in that order).

| Field | Type | Notes |
|---|---|---|
| `crate_name` | `CrateName` | Echoed |
| `version` | `CrateVersion` | The resolved version |
| `rustc_version` | `WireRustcVersion` | Current stable channel release (cached 60 min in the scheduler DO) |
| `targets` | `CrateRequestTarget[]` | Per-target outcome, `CI_TARGET_TRIPLES` order |

`CrateRequestTarget`:

| Field | Type | Notes |
|---|---|---|
| `target` | `TargetTriple` | The CI target |
| `state` | `CrateRequestState` | `cached` \| `queued` \| `already_queued` \| `building` |
| `task_id` | `string?` | Scheduler task id for the root crate on this target; absent when `state` is `cached` |
| `human_lane_position` | `u32?` | 1-based position among pending human-lane tasks; `null` unless still pending there |

```json
{
  "crate_name": "serde_json",
  "version": "1.0.149",
  "rustc_version": "1.98.1",
  "targets": [
    {
      "target": "x86_64-unknown-linux-gnu",
      "state": "queued",
      "task_id": "serde_json-1.0.149-4f0a…-x86_64_unknown_linux_gnu-1_98_1",
      "human_lane_position": 1
    },
    {
      "target": "aarch64-apple-darwin",
      "state": "already_queued",
      "task_id": "serde_json-1.0.149-4f0a…-aarch64_apple_darwin-1_98_1",
      "human_lane_position": 2
    },
    {
      "target": "x86_64-pc-windows-msvc",
      "state": "cached",
      "task_id": null,
      "human_lane_position": null
    }
  ]
}
```

Errors: `400` for a malformed feature name, `401` when siteverify
rejects the token, `404` when the crate (or the requested exact
version) is not published on crates.io.

## `GET /api/v1/requests/{task_id}`

`{task_id}` is a value returned in `task_id` above. Response `200`:
`RequestStatus`.

| Field | Type | Notes |
|---|---|---|
| `task_id` | `string` | The task's canonical id |
| `crate_name`, `version`, `features_json`, `target`, `rustc_version` | identity newtypes | The task's queue identity |
| `lane` | `TaskLane` | `miss` \| `human` |
| `status` | `QueueTaskStatus` | `pending` \| `dispatched` \| `running` \| `completed` \| `failed` |
| `human_lane_position` | `u32?` | 1-based position among pending human-lane tasks; `null` otherwise |

```json
{
  "task_id": "serde_json-1.0.149-4f0a…-x86_64_unknown_linux_gnu-1_98_1",
  "crate_name": "serde_json",
  "version": "1.0.149",
  "features_json": ["preserve_order"],
  "target": "x86_64-unknown-linux-gnu",
  "rustc_version": "1.98.1",
  "lane": "human",
  "status": "pending",
  "human_lane_position": 1
}
```

`404` when the id is not in the scheduler queue.
