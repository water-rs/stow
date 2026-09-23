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
| `STOW_EDGE_URL` | `https://stow.waterui.dev` | HTTPS URL of the edge worker — the CLI streams bundles from `/api/v1/artifacts/…` (the byte path) and posts `/api/v1/admissions` (miss minting) and `/api/v1/enqueue` (PoW redemption) to it. Falls back to `edge_url` in `~/Library/Application Support/stow/config.toml` (macOS) or `~/.config/stow/config.toml` (Linux), then to the production edge. |
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
| `STOW_PREFETCH_ARTIFACTS_JSON` | wired by parent | JSON-encoded `Vec<PrefetchArtifactRow>` — (crate, c_metadata, bundle_digest) triples to stream through the edge byte path — each checked against its `bundle_digest` — before any rustc invocation. |
| `STOW_CACHE_POLICY_PATH` | wired by parent | Directory of `allow/<target>/<c_metadata>` marker files. The wrapper only consults the public cache for invocations with a marker; the parent `stow check` writes the markers from the local index analysis. |
| `STOW_SUPERVISOR_ENDPOINT` / `STOW_SUPERVISOR_TOKEN` | wired by parent `stow check`/`build`/`test` | Endpoint (`unix:<path>` or `tcp:<port>`) and bearer token of the supervising run the wrapper delegates each invocation to. An endpoint that is set but unusable fails the build; unset means standalone mode, where the wrapper decides in-process. |
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
| `STOW_EDGE_URL` | _required_ | Edge base URL the admin's trusted calls go to: scheduler task submits, `panic on\|off\|status` (the `/api/v1/admin/panic` circuit breaker) and the admin index GET (`/api/v1/admin/index/{target}/{rustc_version}`). |
| `GH_TOKEN` / `GITHUB_TOKEN` | falls back to `gh auth token` | Operator GitHub credential for the edge's trusted endpoints and the GitHub REST calls (`runs`, `cache`, `preheat projects generate`); the owner must have push access to `water-rs/stow`. |
| `CF_ACCOUNT_ID` | _required for `preheat missed`_ | Cloudflare account ID the Analytics Engine SQL API URL is built from. |
| `CF_ANALYTICS_TOKEN` | _required for `preheat missed`_ | Cloudflare API token with `Account Analytics: Read`, used to query the `stow_cache_misses` dataset. In CI it comes from the `CF_ANALYTICS_TOKEN` repository secret (see `DEPLOYMENT.md`). |

`stow-admin index export --target <t> --rustc-version <v> --out <file>`
pages the admin index endpoint for one `(target, rustc)` slice, assembles
the `ArtifactIndex` (`stow_types::index`), writes it zstd-compressed to
`--out`, and prints a one-line JSON summary (`rows`, `bytes`, `sha256`,
`content_sha256`, `tag`) — the same export
`.github/workflows/index-publish.yml` runs for every CI target.

## stow-build (CI runner)

The runner has four subcommands. `stow-build build --output-dir <dir>` is
the untrusted stage (compiles the task crate, writes task, plan and blobs
into `<dir>`); `stow-build publish --input-dir <dir>` is the trusted stage
(validates `<dir>`, then pushes, signs, registers and reports);
`stow-build backfill-bundles [--batch N]` is the one-time migration that
publishes `<tag>.bundle` for rows registered before bundles existed (see
`DEPLOYMENT.md`); `stow-build serve --listen <host:port>` is the dev-only
local dispatch endpoint. Both stages read the task from
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
| `GHCR_USERNAME` / `GHCR_TOKEN` | publish | Credentials for `oci-client` to push bundles to GHCR. Required. |
| `STOW_EDGE_URL` | publish, serve | Edge base URL for `/api/v1/admin/artifacts/register`. Required. |
| `STOW_OIDC_AUDIENCE` | publish (Actions) | `aud` the run requests when it mints its OIDC token; must equal the edge's `STOW_OIDC_AUDIENCE` var. Required in Actions. |
| `GH_TOKEN` / `GITHUB_TOKEN` | serve (falls back to `gh auth token`) | Developer GitHub credential the edge's trusted endpoints accept outside Actions. |
| `SCHEDULER_URL` | publish, serve | The edge `/api/v1/scheduler` URL that receives `/complete` reports. Required. |
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
| `STOW_STATS` | _required_ (Analytics Engine binding) | `stow_events` dataset — sampled served-hit events (see [`PRIVACY.md`](../PRIVACY.md)). |
| `STOW_STATS_SALT_SECRET` | _required_ (secret) | HMAC-SHA256 key the daily-salted install hash is derived from; the derived daily key is never stored. |
| `CF_ACCOUNT_ID` | _required_ (var) | Cloudflare account id the Analytics Engine SQL API is queried under for `GET /api/v1/stats`. |
| `CF_ANALYTICS_TOKEN` | _required_ (secret) | API token with Analytics Engine read on the account — the `Authorization: Bearer` credential `GET /api/v1/stats` queries with. |
| `SCHEDULER` | _required_ (Durable Object binding) | Build scheduler queue. |
| `GITHUB_REPO` | `water-rs/stow` | Repo every trusted credential must resolve inside (OIDC `repository` claim and the push-permission check), and the repository the scheduler triggers `workflow_dispatch` of `build-crate.yml` on. |
| `STOW_OIDC_AUDIENCE` | _required_ (var) | `aud` the edge pins on Actions OIDC tokens; must equal the repo variable CI requests. |
| `GHCR_BASE_URL` | `https://ghcr.io/v2/water-rs/stow-cache` | OCI base URL (`scheme://host/v2/repository`) the edge's bundle byte path pulls from; a mock deploy points it at `stow-mock-registry serve`. |
| `STOW_BATCH_FETCH_CONCURRENCY` | `32` | Concurrent crates.io metadata fetches while `/api/v1/admissions` resolves a graph's cold direct entries. |
| `STOW_MAX_EXPANDED_TASKS` | `4096` | Cap on the size of an expanded transitive graph. |
| `STOW_LOCAL_CI_URL` | unset | When set, the scheduler dispatches to this URL instead of GitHub `workflow_dispatch`. Used by mock fixtures. |
| `STOW_RUSTC_DATA_BASE_URL` | `https://raw.githubusercontent.com/water-rs/stow/dev/resolve/rustc-data` | Base URL serving the generated `resolve/rustc-data/` tree. When a resolve asks for a `rustc -vV`/`--print cfg` pair missing from the vendored bundle (a stable rustc newer than the deploy), the worker fetches `{base}/<version>/verbose/{host}.txt` and `{base}/<version>/cfg/{triple}.txt` from here — the scheduled `rustc-data.yml` job keeps the tree current, so a channel bump needs no worker redeploy. Unset restricts resolves to vendored versions. |
| `STOW_DISPATCH_MIN_AGE_MINUTES` | `5` | Minimum age (minutes) a task must wait in `pending` before being dispatched, so misses can coalesce. Mock fixtures set `0`. |
| `STOW_MAX_CONCURRENT_JOBS` | `45` | Maximum concurrently dispatched CI builds across all runner families. Sized against the org's 60-runner pool, leaving 15 runners for the repo's own CI. Mock fixtures set `3` because miniflare OOMs under parallel register/complete bursts. |
| `STOW_MAX_CONCURRENT_MACOS_JOBS` | `16` | Maximum concurrently dispatched CI builds on macOS targets (`aarch64-apple-*`). The org has 20 macOS runners; the cap leaves 4 for the repo's own CI, and macOS rows past the cap stay pending until a slot frees. |
| `STOW_STALE_DISPATCH_MINUTES` | `60` | Age after which a `dispatched` task with no completion is assumed lost and re-queued. Must exceed the slowest expected CI build or long builds get double-dispatched. |
| `STOW_POW_CHALLENGE_SECRET` | _required_ (secret) | HMAC-SHA256 key for the enqueue-admission challenge minted on public cache misses and verified by `POST /api/v1/enqueue`. |
| `STOW_POW_MIN_BITS` | `12` | Floor on enqueue proof-of-work difficulty: minted admissions and redeemed tickets never require fewer bits, even on an empty queue. |
| `STOW_MAX_QUEUE_PENDING` | `2000` | Pending-task count at which the miss lane refuses `POST /api/v1/enqueue` with 429 and `Retry-After: 600`. Checked in the edge handler before forwarding and again inside the scheduler Durable Object; human-lane and RepoWriter-trusted submits are exempt. |
| `STOW_HUMAN_MAX_CLOSURE` | `150` | Largest dependency closure `POST /api/v1/requests` accepts per target; larger closures are refused with 422 naming the size and the cap. |
| `STOW_HUMAN_DAILY_TASK_BUDGET` | `2000` | Human-lane tasks the scheduler accepts per UTC day. The Durable Object keeps the counter (`human_daily_task_budget` table) and refuses an overspending submit with 429; the edge sets `Retry-After` to seconds until 00:00 UTC. |
| `TURNSTILE_SITE_KEY` | `0x4AAAAAAE8LjhnMsqdVhiSp` | Public site key of the invisible Turnstile widget the request page renders; paired with `TURNSTILE_SECRET_KEY`. Mock fixtures use Cloudflare's always-pass test key `1x00000000000000000000AA`. |
| `TURNSTILE_HOSTNAME` | `stow.waterui.dev` | Hostname the Turnstile widget is registered for; a `POST /api/v1/requests` token whose siteverify report names another host is rejected `hostname-mismatch`. Mock fixtures use `example.com`, the hostname Cloudflare's test keys always report. |
| `TURNSTILE_SECRET_KEY` | _required_ (secret) | Turnstile secret key the worker posts to siteverify for `POST /api/v1/requests` token checks. Never logged or returned in a response. Mock fixtures use the always-pass test secret `1x0000000000000000000000000000000AA`; production deploys source it from the `STOW_TURNSTILE_SECRET_KEY` repository secret. |
| `GITHUB_APP_ID` / `GITHUB_APP_INSTALLATION_ID` | `4985635` / `162649982` | The `stow-ci` GitHub App's ID and its installation ID on `water-rs`. Required when `STOW_LOCAL_CI_URL` is unset. |
| `GITHUB_APP_PRIVATE_KEY` | _required when STOW_LOCAL_CI_URL is unset_ (secret) | The App's private-key PEM. The scheduler signs an RS256 JWT with it (WebCrypto) and exchanges it for an installation token that authorizes `workflow_dispatch`; the App needs **Actions: Read and write**. The token is cached in the Durable Object's SQL storage while more than 5 minutes of validity remain. Deploy jobs source it from the `STOW_APP_PRIVATE_KEY` repository secret — the same one release-plz uses. |
