# Environment variable reference

Single source of truth for every env var a user or operator sets on stow.
Variables a stow process wires for its own children appear where they
explain the wrapper's behavior; the rest of the internal plumbing
(`STOW_RUSTC_EXTRA_ARGS`) and the sandbox test hooks are omitted on
purpose. Each row lists the component(s) that read the variable, the
default, and the purpose.

## CLI / wrapper (`stow`, `cargo-stow`)

| Variable | Default | Purpose |
|---|---|---|
| `STOW_EDGE_URL` | `https://stow.waterui.dev` | HTTPS URL of the edge worker — the CLI streams bundles from `/api/v1/bundles/{digest}` (the byte path) and posts `/api/v1/admissions` (miss minting) and `/api/v1/enqueue` (PoW redemption) to it. Falls back to `edge_url` in `~/Library/Application Support/stow/config.toml` (macOS) or `~/.config/stow/config.toml` (Linux), then to the production edge. |
| `STOW_REGISTRY_BASE_URL` | `https://ghcr.io/v2/water-rs/stow-cache` | OCI base URL (`scheme://host/v2/repository`) the CLI pulls signed index slices from (bundle bytes stream through the edge). Override for mock-registry runs; `registry_base_url` in the config file does the same. |
| `STOW_INDEX_REFRESH_SECS` | `600` | Seconds a cached index slice may sit before the driver revalidates its manifest digest against the registry. `index_refresh_secs` in the config file. |
| `STOW_CACHE_BUDGET_SECS` | `150ms x covered units, capped at 30` | Seconds the pre-cargo work budget lasts — the graph analysis and blocking prefetch a `stow check`/`build`/`test` pays before handing off to cargo; what is not prefetched is fetched on demand by the wrapper. `0` disables the pre-build phase entirely, the cheapest way to measure stow's overhead against a plain cargo run. |
| `STOW_VERIFY_MODE` | `github-ci` | `github-ci` enforces fulcio-rooted cosign verification; `mock-key` accepts a single PEM public key for local mock and exists only in a `stow-cli` built with the `mock-verify` cargo feature (release binaries reject it). |
| `STOW_MOCK_PUBLIC_KEY_PATH` | _required when `STOW_VERIFY_MODE=mock-key`_ | PEM path the wrapper trusts when verifying mock OCI bundles. |
| `STOW_CACHE_DIR` | `~/.stow` | Where the local artifact cache + state SQLite live. |
| `STOW_ARTIFACT_CACHE_MAX_BYTES` | `21474836480` (20 GiB) | Soft cap on the local artifact cache before stow purges old entries. |
| `STOW_DISABLE_PUBLIC_CACHE` | unset | When set (any value), the wrapper bypasses the public cache for the rest of the cargo run. The parent `stow check` sets this for nightly/beta toolchains. |
| `STOW_PUBLIC_CACHE_RUSTC_VERSION` | unset | Set by the parent `stow check` so the per-rustc wrapper does not reprobe `rustc -vV`. |
| `STOW_PUBLIC_CACHE_TARGET` | unset | Same as above for the target triple. |
| `STOW_CONFIG_BLOB` | unset | JSON-encoded resolved `StowConfig`. The parent `stow check` writes this so each rustc-wrapper child skips re-parsing the user config file. |
| `STOW_CACHED_ARTIFACT_MATERIALIZATION` | `reflink-or-copy` | Set to `symlink` to symlink cached artifacts into the target dir instead of reflinking/copying. APFS clones share storage; symlinks share inodes. |
| `STOW_TRACE_FILE` | unset | When set, stow writes a Chrome-format trace covering every `stow.*` span. Open in chrome://tracing or perfetto.dev. |
| `STOW_TRACE_WRAPPED_COMPILERS` | unset | When set, the wrapper emits tracing for every wrapped `rustc` / `cc` invocation (verbose). |
| `STOW_IDENTITY_TRACE` | unset | Directory the wrapper writes one JSON identity record per `rustc` invocation into (`IdentityTraceRecord`: the parsed inputs — target, rustc, emit, crate types, profile, features, dependency `c_metadata` chain — plus the computed compile key and `c_metadata`). The answer to "why did this unit miss" — diff the record for the missing unit against the index row it should have hit. Inert when unset. |
| `STOW_ENABLE_SEMANTIC_FALLBACK` | wired by parent `stow check` | When `1`, the per-rustc wrapper falls back to a semver-relaxed lookup in the cached index slice after an exact-key miss. |
| `STOW_ENABLE_PREBUILT_DEPS` | unset (off) | When set to anything but `0`, enables the experimental top-crate fast path: `stow check` materializes a workspace whose every direct dependency is already cached, so the run compiles only the top crate. Off by default; the regular per-unit inject path is unaffected either way. |
| `STOW_EXPANDED_GRAPH_JSON` | wired by parent | JSON-encoded transitive `Vec<DependencyGraphEntry>` so the wrapper can validate a semantic candidate against the user's lockfile. |
| `__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS` | `nightly`, set on the `--unit-graph` query child only | Cargo's own channel override: makes the wrapped cargo accept `-Z unstable-options` on a stable toolchain while rustc — which never reads it — keeps answering probes as stable. Set only when the channel is stable and the user has no `RUSTC_BOOTSTRAP` of their own. |
| `STOW_PREFETCH_ARTIFACTS_JSON` | wired by parent | JSON-encoded `Vec<PrefetchArtifactRow>` — (crate, c_metadata, bundle_digest) triples to stream through the edge byte path — each checked against its `bundle_digest` — before any rustc invocation. |
| `STOW_CACHE_POLICY_PATH` | wired by parent | Directory of `allow/<target>/<c_metadata>` marker files. The wrapper only consults the public cache for invocations with a marker; the parent `stow check` writes the markers from the local index analysis. |
| `STOW_SUPERVISOR_ENDPOINT` / `STOW_SUPERVISOR_TOKEN` | wired by parent `stow check`/`build`/`test` | Endpoint (`unix:<path>` or `tcp:<port>`) and bearer token of the supervising run the wrapper delegates each invocation to. An endpoint that is set but unusable fails the build; unset means standalone mode, where the wrapper decides in-process. |
| `STOW_SERVE_MAP_FILE` | wired by parent `stow build`/`check`/`test` | Path to the build's serve map file, a JSON `{"target": [[name, version], ...], "host": [[name, version], ...], "pending": bool}` written atomically under `graph_plan_dir()` — the canonical `(crate, version)` pairs the build's index slices and local cache could serve, per side of the unit graph (`"*"` version = any semver-compatible version). The rustc facade reads it before starting its runtime: a unit the map does not cover compiles immediately, reporting over one-way supervisor frames; a covered unit — or any invocation with no map — takes the plan round trip. `pending: true` means the map was written from the cached slices alone while the fresh index fetch was still running: a facade whose crate the map names at some version or side but whose unit it does not cover then sends one `AwaitServeMap` frame over the build's supervisor transport (unix socket or loopback TCP — the same transport the Windows build uses) and the supervisor answers once the build's background analysis has written the final map, or at once when it already has; the read carries a bounded timeout and a dead driver ends the wait by dropping the connection, so the facade always decides on the map it then finds. A facade whose crate the map never covered — at any version, on either side — does not wait on the fetch at all. The build's background analysis rewrites the file mid-build once the full graph resolves; an absent file reads as an empty map. |
| `STOW_WRAPPER_PATH` | unset | Overrides the runtime wrapper binary `stow setup` points the cargo config at (defaults to the current executable). |
| `CC` / `CXX`, and the `cc` crate's scoped forms (`CC_<triple>`, `CXX_<triple>`, `TARGET_CC`/`HOST_CC`, `TARGET_CXX`/`HOST_CXX`) | platform compiler | The C/C++ toolchain the caller configured for a target, in the precedence order the `cc` crate reads it. `stow setup` consults all of them; a configured toolchain is recorded as `STOW_REAL_CC`/`STOW_REAL_CXX`, and setup writes the shims under `CC_<host triple>`/`CXX_<host triple>` so only the host target routes through stow — other targets keep the compiler cc-rs would pick. |
| `STOW_REAL_CC` / `STOW_REAL_CXX` | unset | Written by `stow setup` (and by `stow build`/`check`/`test` for their children) only when a toolchain was configured — the executable the `stow-cc`/`stow-cxx` shims then exec. When unset, a shim resolves the platform's compiler per invocation the way the `cc` crate does: on an msvc target, `find_msvc_tools` for `cl.exe` with that toolchain's environment applied to the child — nothing is persisted, so a Visual Studio update never strands the wiring. |
| `TARGET` | set by cargo | The build target the `stow-cc`/`stow-cxx` shims resolve their compiler for — how an x64→aarch64 cross build picks the aarch64 `cl.exe`. Build scripts get it from cargo; outside one, a shim assumes the host target. |
| `CMAKE_C_COMPILER_LAUNCHER` / `CMAKE_CXX_COMPILER_LAUNCHER` | set by `stow setup` | The `stow-cc-launcher` shim, wired in the global `[env]` table. CMake has no target-scoped form of these, so they stay bare; the launcher wraps whichever compiler CMake picks and runs it through the same cache path as the `CC`/`CXX` shims. |
| `RUSTFLAGS` / `CARGO_ENCODED_RUSTFLAGS`, `CARGO_TARGET_<triple>_LINKER` | unset | Cargo's own flag and linker env sources — read, never written, by stow's linker resolution when it decides whether the configuration already selects a reachable mold. |
| `COMPILER_PATH` | set by `stow setup` | Written into the global `[env]` table on Linux — the managed mold install's `bin` dir, where the compiler driver finds `ld.mold`. Deliberately an env var, not a rustflag, so it never enters the compile key. |
| `CARGO_HOME` | unset | Cargo's own home — `stow setup` writes its wrapper wiring into `$CARGO_HOME/config.toml`, resolving it exactly as cargo does (the variable, else `~/.cargo`). |
| `STOW_CLI_GITHUB_TOKEN` | falls back to `GITHUB_TOKEN`, then `GH_TOKEN` | GitHub token `stow update` sends with its release lookups — only useful against rate limits or a private mirror. |
| `STOW_NO_ANALYTICS` | unset | When `1`, every edge request carries `x-stow-no-analytics: 1` and the edge writes no usage-statistics point and computes no install hash for it. See [`PRIVACY.md`](../PRIVACY.md). |
| `RUST_LOG` | unset | Standard tracing-env-filter directive (e.g., `stow_cli=debug,info`). |

`stow stats` prints this install's own cache counters (`--json` for
JSON) and sends nothing.

## stow-admin

| Variable | Default | Purpose |
|---|---|---|
| `STOW_EDGE_URL` | _required for the edge-backed commands_ | Edge base URL the admin's trusted calls go to: scheduler task submits (including `request resolve`'s `/api/v1/scheduler/requests/{id}/outcome` post), `scheduler demand-feed` (the `/api/v1/admin/scheduler/demand-feed/*` input lane — see the demand-feed runbook below), `dispatch-freeze status\|clear` (the `/api/v1/admin/dispatch-freeze` recovery path), `index sync` and the admin index GET (`/api/v1/admin/index/{target}/{rustc_version}`). Its host is also the `http.host` term `maintenance ensure`/`on`/`off` write into the zone's WAF rules. `preheat manual` and `index export`/`publish` never read it — they run against GitHub and GHCR only. |
| `STOW_EDGE_VERSION_OVERRIDE` | _optional_ | Verbatim `Cloudflare-Workers-Version-Overrides` header value (e.g. `stow-edge="<version-id>"`) pinned onto every edge call — `deploy-edge.yml` sets it so `scheduler migrate` runs on the uploaded candidate before traffic shifts. |
| `GH_TOKEN` / `GITHUB_TOKEN` | falls back to `gh auth token` | Operator GitHub credential for the edge's trusted endpoints and the GitHub REST calls (`runs`, `cache`, `preheat projects generate`); the owner must have push access to `water-rs/stow`. |
| `CF_ACCOUNT_ID` | _required for `preheat missed` and `watchdog`_ | Cloudflare account ID the Analytics Engine SQL API URL is built from. |
| `CF_ZONE_ID` | _required for `maintenance` and `watchdog`_ | Cloudflare zone ID of `waterui.dev`, whose `http_request_firewall_custom` phase holds the three `stow maintenance:` WAF rules. In CI it is the `CF_ZONE_ID` repository variable. |
| `CF_ANALYTICS_TOKEN` | _required for `preheat missed`_ | Cloudflare API token with `Account Analytics: Read`, used to query the `stow_cache_misses` dataset. In CI it comes from the `CF_ANALYTICS_TOKEN` repository secret (see `DEPLOYMENT.md`). |
| `STOW_CF_ANALYTICS_SQL_BASE` | unset | **Mock/test-only.** Overrides the Analytics Engine SQL API base URL (`https://api.cloudflare.com/client/v4`) `preheat missed` posts its `stow_cache_misses` query to, so the workflow-entrypoint e2e can point the lane at a loopback fixture. Production never sets it — the constant is the only live endpoint — and like `STOW_STATS_SQL_URL` the URL must stay loopback-pinned: `CF_ANALYTICS_TOKEN` rides in the `Authorization` header, so a non-loopback URL would exfiltrate it. |
| `CLOUDFLARE_API_TOKEN` | _required for `watchdog`, `deploy verdict` and `maintenance`_ | Cloudflare API token. The watchdog queries the GraphQL analytics and Analytics Engine APIs with it and sends the alert mail through the Email Sending REST API (`POST /accounts/{id}/email/sending/send`); `deploy verdict` queries the GraphQL Analytics API (`workersInvocationsAdaptive`, `durableObjectsInvocationsAdaptiveGroups`, `durableObjectsPeriodicGroups`, `d1AnalyticsAdaptiveGroups`); `maintenance` toggles the zone's WAF maintenance rules. Needs `Account Analytics:Read`, Email Sending and `Zone WAF:Edit` on `waterui.dev`. In CI it is the `CLOUDFLARE_API_TOKEN` repository secret — see `DEPLOYMENT.md`. |
| `STOW_OIDC_AUDIENCE` | _required in Actions_ | `aud` the admin requests when it mints a GitHub Actions OIDC token for an edge call; must equal the edge's `STOW_OIDC_AUDIENCE` var. Set from `vars.STOW_OIDC_AUDIENCE` in the workflow. |
| `ACTIONS_ID_TOKEN_REQUEST_URL` / `ACTIONS_ID_TOKEN_REQUEST_TOKEN` | injected by Actions | Endpoint + bearer the runtime exposes for OIDC mints; the admin reads both to mint a fresh token per edge call. Absent them (outside Actions), the admin uses `GH_TOKEN`. |
| `STOW_REGISTRY_BASE_URL` | production GHCR | OCI base URL (`scheme://host/v2/repository`) `index export`/`preheat manual` pull records, bundles and published slices from — anonymously, signatures verified. Override for mock-registry runs. |
| `STOW_MOCK_PUBLIC_KEY_PATH` | unset | Mock cosign key `index export`/`preheat manual` verify records and index slices against under a mock registry — the `mock-verify` code path, never production. |
| `STOW_CACHE_DIR` | `~/.cache/stow` | Fulcio/Rekor trust material cache for `index export` and `preheat manual` signature verification. |

`stow-admin index export --out-dir <dir>` lists the registry's
`records-*` tags once, pulls and verifies only the records artifacts the
previous slices' folded sets have not covered (each is signed by the
`build-crate.yml` cosign identity — a signature that fails the pin is
fatal), folds the previous rows plus the new ones into every
`(target, rustc)` `ArtifactIndex` (`stow_types::index`), writes each
slice zstd-compressed under `--out-dir`, and prints a one-line JSON
summary per slice (`rows`, `bytes`, `sha256`, `content_sha256`, `tag`)
plus `new-records.json`, the records this pass newly folded —
`.github/workflows/index-publish.yml` runs the same export for every CI
target, and `index sync` POSTs exactly those new rows to the edge's
`/api/v1/admin/artifacts/sync` so the D1 catalog stays a mirror.
`--full` ignores the folded sets and re-pulls everything — for the first
publish of a new rustc and for disaster recovery.

`stow-admin preheat manual --crates|--projects <file> --rustc-version <v>
[--targets a,b] [--in-flight 45] [--edge-url <url>] [--dispatch-url
<url>]` is the operator-driven wave of stow#455: it resolves the graph
in-process for every CI target, layers it so each layer's deps sit in
the published index, dispatches `build-crate.yml` through GitHub's
`workflow_dispatch` API under the operator token, dispatches
`index-publish.yml` between layers, and resumes by re-reading the
published index — no edge, no local state. A `--projects` repository
that fails to resolve is reported while the wave dispatches the rest,
and the run exits non-zero naming it; a `--crates` or `--dirs` failure
still aborts before dispatch. `--dispatch-url` points the
wave at the mock's local CI server (`GET /tasks` polling, in-process
index publish) for `scripts/mock-e2e.sh`.

## stow-build (CI runner)

The runner has three subcommands. `stow-build build --output-dir <dir>` is
the untrusted stage (compiles the task crate, writes task, plan and blobs
into `<dir>`); `stow-build publish --input-dir <dir>` is the trusted stage
(validates `<dir>`, then pushes and signs the bundle plus the task's
records artifact into GHCR — GitHub's `workflow_run` webhook reports
the run, so publish never calls the edge); `stow-build serve --listen
<host:port>` is the dev-only local dispatch endpoint. Both stages read the task from
`STOW_BUILD_TASK_JSON`, which the workflow fills from its
`workflow_dispatch` input.

| Variable | Stage | Purpose |
|---|---|---|
| `STOW_BUILD_TASK_JSON` | build, publish | Inline JSON `BuildTaskPayload`. Required. |
| `STOW_BUILD_WORKSPACE_ROOT` | build | Pre-existing path to build in instead of a tempdir. |
| `STOW_BUILD_CARGO_SUBCOMMAND` | build | One of `build` / `check` / `test`. Default `build`. |
| `STOW_BUILD_RUSTC_CAPTURE_DIR` | build (set by the runner for its rustc wrapper) | Per-rustc-invocation capture sink for output snapshots and identity sidecars. |
| `STOW_BUILD_CAPTURE_IPC` | build (set by the runner inside the heel sandbox) | IPC socket the rustc wrapper streams capture records to; the host collector, not the wrapper, owns record persistence. |
| `STOW_BUILD_WRAPPER_CRATE_NAME` | build (set by the runner inside the heel sandbox) | Package name of the generated wrapper package the task crate builds under; the rustc wrapper records its units as observed scaffolding, never publishable artifacts. |
| `STOW_GLIBC_SYSROOT` | build (set by the Linux leg of `build-crate.yml`) | Root of the glibc-2.28 sysroot the Linux build job installs under `$HOME/stow-glibc-2.28` — the heel sandbox grants the whole tree to the untrusted crate build so its compiles and links read the sysroot's headers and libraries. The job's PATH shim dir (`<root>/bin`, canonical driver names carrying `-B`/`--sysroot`) is reached through the `PATH` passthrough; `STOW_GLIBC_SYSROOT` itself rides the toolchain passthrough like every other `CC_*`/`CARGO_TARGET_*` variable. |
| `GHCR_USERNAME` / `GHCR_TOKEN` | publish | Credentials for `oci-client` to push bundles to GHCR. Required. |
| `STOW_EDGE_URL` | serve | Edge base URL the local server's `workflow_run` webhook POSTs to. Required. |
| `STOW_GITHUB_WEBHOOK_SECRET` | serve | HMAC key the webhook signature is computed with — the same value the edge verifies `X-Hub-Signature-256` against. Required. |
| `STOW_OIDC_AUDIENCE` | publish (Actions) | `aud` for the edge OIDC token minted when a publish step calls a trusted edge route (`index publish` D1 sync); unused when the run only pushes GHCR artifacts. |
| `GH_TOKEN` / `GITHUB_TOKEN` | serve (falls back to `gh auth token`) | Developer GitHub credential the edge's trusted endpoints accept outside Actions. |
| `STOW_MOCK_PUBLIC_KEY_PATH` / `STOW_MOCK_PRIVATE_KEY_PATH` / `STOW_MOCK_REGISTRY_ROOT` | serve | Mock cosign key pair and mock registry root the local dispatcher populates. Required. |

## stow-mock-registry

| Variable | Default | Purpose |
|---|---|---|
| `RUST_LOG` | unset | Standard tracing filter. |

The mock registry is a one-shot CLI; everything else is positional args.

## edge worker (Cloudflare bindings, set in `wrangler.toml`/`Skyzen.toml`)

| Binding | Default | Purpose |
|---|---|---|
| `STOW_DB` | _required_ (D1 binding) | Artifact catalog database. |
| `STOW_ANALYTICS` | _required_ (Analytics Engine binding) | `stow_cache_misses` dataset — every cache miss is one data point here, so demand analytics never spend D1 row writes. |
| `CF_ACCOUNT_ID` | _required_ (var) | Cloudflare account id the Analytics Engine SQL API is queried under for `GET /api/v1/stats`. |
| `CF_ANALYTICS_TOKEN` | _required_ (secret) | API token with Analytics Engine read on the account — the `Authorization: Bearer` credential `GET /api/v1/stats` queries with. |
| `SCHEDULER` | _required_ (Durable Object binding) | Build scheduler queue. |
| `GITHUB_REPO` | `water-rs/stow` | Repo every trusted credential must resolve inside (OIDC `repository` claim and the push-permission check), and the repository the scheduler triggers `workflow_dispatch` of `build-crate.yml` on. |
| `STOW_OIDC_AUDIENCE` | _required_ (var) | `aud` the edge pins on Actions OIDC tokens; must equal the repo variable CI requests. |
| `GHCR_BASE_URL` | `https://ghcr.io/v2/water-rs/stow-cache` | OCI base URL (`scheme://host/v2/repository`) the edge's bundle byte path pulls from; a mock deploy points it at `stow-mock-registry serve`. |
| `STOW_MAX_EXPANDED_TASKS` | `4096` | Cap on the size of an expanded transitive graph. |
| `STOW_LOCAL_CI_URL` | unset | When set, the scheduler dispatches to this URL instead of GitHub `workflow_dispatch`. Used by mock fixtures. |
| `STOW_SCHEDULER_BUDGET` | unset | **Mock-only.** When `"1"`, the Durable Object answers the `/budget` and `/budget/seed` probe routes the workerd cost gate (`scripts/scheduler-budget.sh`) drives. Set only by `edge/Skyzen.mock.toml`; a test asserts it never appears in `edge/Skyzen.toml`, so the probe cannot reach production. |
| `STOW_STATS_SQL_URL` | unset | **Mock-only.** Overrides the Analytics Engine SQL API base URL the public stats routes post to (`/stats` and friends) — and the edge-side override the demand feed's `analytics_engine/sql` query posts through in the mock deploy. Loopback-pinned — the account's analytics token rides in the `Authorization` header, so a non-loopback URL would exfiltrate it; set only by `edge/Skyzen.mock.toml` (to `stow-mock-registry serve`'s stub) and pinned out of `edge/Skyzen.toml` by the same manifest test as `STOW_LOCAL_CI_URL`. |
| `STOW_DISPATCH_MIN_AGE_MINUTES` | `5` | Minimum age (minutes) a task must wait in `pending` before being dispatched, so misses can coalesce. Mock fixtures set `0`. |
| `STOW_MAX_CONCURRENT_JOBS` | `45` | Maximum concurrently dispatched CI builds across all runner families. Sized against the org's 60-runner pool, leaving 15 runners for the repo's own CI. Mock fixtures set `3` because miniflare OOMs under parallel complete bursts. `"0"` pauses dispatch: submits keep queueing, nothing is claimed, and the alarm wakes only for stale recovery on builds already in flight — see `DEPLOYMENT.md`'s pause procedure. |
| `STOW_MAX_CONCURRENT_MACOS_JOBS` | `16` | Maximum concurrently dispatched CI builds on macOS targets (`aarch64-apple-*`). The org has 20 macOS runners; the cap leaves 4 for the repo's own CI, and macOS rows past the cap stay pending until a slot frees. |
| `STOW_STALE_DISPATCH_MINUTES` | `60` | Age after which a `dispatched` task with no completion is assumed lost and re-queued. Must exceed the slowest expected CI build or long builds get double-dispatched. |
| `STOW_POW_CHALLENGE_SECRET` | _required_ (secret) | HMAC-SHA256 key for the enqueue-admission challenge minted on public cache misses and verified by `POST /api/v1/enqueue`. |
| `STOW_POW_MIN_BITS` | `12` | Floor on enqueue proof-of-work difficulty: minted admissions and redeemed tickets never require fewer bits, even on an empty queue. |
| `STOW_MAX_QUEUE_PENDING` | `2000` | Pending-task count at which the miss lane refuses `POST /api/v1/enqueue` with 429 and `Retry-After: 600`. Checked in the edge handler before forwarding and again inside the scheduler Durable Object; human-lane and RepoWriter-trusted submits are exempt. |
| `STOW_HUMAN_MAX_CLOSURE` | `150` | Largest single-target uncovered closure a request may need. The admitted value rides the `resolve-request.yml` dispatch; the job's resolve fails a request whose largest uncovered target closure exceeds it, so the record ends `failed` naming the size and the cap. |
| `STOW_HUMAN_DAILY_TASK_BUDGET` | `2000` | Human-lane tasks the scheduler accepts per UTC day. The Durable Object keeps the counter (`human_daily_task_budget` table) and refuses an overspending submit with 429; the edge sets `Retry-After` to seconds until 00:00 UTC. |
| `STOW_MIN_DISPATCH_VALUE` | `0` | Admission floor on a pending row's raw `queue.value` — the pre-cost band integer, not the cost-normalized rank: a miss-lane row claims only while its value reaches the bound — under-floor work stays queued and listed, never built; the human lane is exempt. A nonnegative i64 decimal string; the DO parses it when its settings initialize, so an overflow or negative value surfaces then, not at deploy time. The binding is operator input only — the live floor is the `settings.min_dispatch_value` row `stow-admin scheduler migrate` stamps and backfills `dispatch_eligible` from, so changing the variable requires that migrate pass before it has any effect. |
| `STOW_FREEZE_WINDOW_MINUTES` | `60` | Trailing window (minutes) the dispatch-freeze trip counts terminal attempt outcomes over (the DO's `attempt_outcome_buckets` counters — one five-minute bucket per target, so the read set is window-bounded whatever the traffic). |
| `STOW_FREEZE_MIN_OUTCOMES` | `50` | Sample floor for the trip: a stream (the fleet aggregate or any single target) must reach this many terminal outcomes in the window before its failure ratio is read — below it nothing trips however bad the ratio. |
| `STOW_FREEZE_FAIL_PERCENT` | `50` | Failure ratio (percent, integer-compared) a sufficiently-sampled stream must reach to freeze dispatch — the trip needs both the floor and the ratio, never either alone. |
| `STOW_COST_BUDGET_MULTIPLIER` | `1.0` | Scales the scheduler DO's daily SQL budget — it self-meters `rowsRead`/`rowsWritten` off every statement's cursor and freezes dispatch the moment the day passes (monthly Workers Paid allowance / 30) × this value; `0.5` trips at half the allowance. `edge/Skyzen.mock.toml` inflates it (`10000`) so the budget probe's destructive fixture seeds — millions of billed writes — never trip the freeze; the production value lives in `edge/Skyzen.toml`. |
| `STOW_ALERT_FROM` | `alerts@stow.waterui.dev` | Sender address of the freeze/clear alert emails; must live on a domain onboarded and Enabled under Compute → Email Service → Email Sending (`E_SENDER_NOT_VERIFIED` otherwise). |
| `STOW_ALERT_TO` | `me@lexo.cool` | Recipient of the freeze/clear transition alert emails — should match the binding's `allowed_destination_addresses`. |
| `STOW_ALERT_EMAIL` | _declared in `Skyzen.toml` only_ (`send_email` binding, `remote = true`) | Email Service send binding the alert emails go through — `send({to, from, subject, text, html})`. The mock/local manifests deliberately omit it, so their alert path resolves to `Disabled` and can never reach Cloudflare's sending API. |
| `TURNSTILE_SITE_KEY` | `0x4AAAAAAE8LjhnMsqdVhiSp` | Public site key of the invisible Turnstile widget the request page renders; paired with `TURNSTILE_SECRET_KEY`. Mock fixtures use Cloudflare's always-pass test key `1x00000000000000000000AA`. |
| `TURNSTILE_HOSTNAME` | `stow.waterui.dev` | Hostname the Turnstile widget is registered for; a `POST /api/v1/requests` token whose siteverify report names another host is rejected `hostname-mismatch`. Mock fixtures use `example.com`, the hostname Cloudflare's test keys always report. |
| `TURNSTILE_SECRET_KEY` | _required_ (secret) | Turnstile secret key the worker posts to siteverify for `POST /api/v1/requests` token checks. Never logged or returned in a response. Mock fixtures use the always-pass test secret `1x0000000000000000000000000000000AA`; production deploys source it from the `STOW_TURNSTILE_SECRET_KEY` repository secret. |
| `GITHUB_APP_ID` / `GITHUB_APP_INSTALLATION_ID` | `4985635` / `162649982` | The `stow-ci` GitHub App's ID and its installation ID on `water-rs`. Required when `STOW_LOCAL_CI_URL` is unset. |
| `GITHUB_APP_PRIVATE_KEY` | _required when STOW_LOCAL_CI_URL is unset_ (secret) | The App's private-key PEM. The scheduler signs an RS256 JWT with it (WebCrypto) and exchanges it for an installation token that authorizes `workflow_dispatch` — the App needs **Actions: Read and write** on `GITHUB_REPO` (deliberately no `issues`: the edge is untrusted serving infrastructure; the `incident` issue record is the watchdog's job). The token is cached in the Durable Object's SQL storage while more than 5 minutes of validity remain. Deploy jobs source it from the `STOW_APP_PRIVATE_KEY` repository secret — the same one release-plz uses. |

### Demand feed (stow#523)

`stow-admin scheduler demand-feed` is the hourly lane between the
`stow_cache_misses` Analytics Engine dataset and the #522 demand
ledger. Semantics the operator knobs expose:

- `--hour YYYY-MM-DDTHH` (UTC, required to be a *closed* hour): the
  explicit recovery path. It is validated before any side effect —
  malformed input and an open hour error out immediately. When the
  durable cursor holds an unfinished hour, `--hour` must name it
  (resume its frozen state); naming any other hour refuses rather than
  silently leap past unfinished work. The default (no flag) resumes
  the cursor first — an unfinished staging attempt re-materializes
  under a fresh generation, a `complete` hour delivers its already
  staged pages without a new query — and only then materializes the
  watermark's canonical successor, which a no-op tick skips.
- The Analytics Engine leg is one `FORMAT JSON` `analytics_engine/sql`
  query per closed hour — `semantic`/`graph` misses weighted
  `sum(_sample_interval * double1)` — honoring the `STOW_NO_ANALYTICS`
  consent at write time: opted-out callers' points are never written,
  never rescaled back. The weight sum is the documented additive
  estimate; today's unsampled `double1 = 1.0` writes keep it exact.
  The response streams to a temp file and validates the whole
  document (meta contract, declared `rows`, terminal EOF) before a
  single page freezes — a late-invalid or truncated body abandons the
  attempt under a fresh generation on the next tick.
- Concurrency: the GitHub hourly job plus a possible manual rerun are
  the only callers; overlapping invocations contend only on the
  DO's serialized storage — the durable cursor is the arbiter, and a
  second job finding the hour frozen delivers rather than
  re-materializing.
- Ordering: the workflow pulls the signed `stow-admin` binary of the
  merge-queue head of `main`; the command ships with this change so
  ticks fail visibly until a released toolchain carries it — no
  per-hour toolchain build, no new alert cron.
