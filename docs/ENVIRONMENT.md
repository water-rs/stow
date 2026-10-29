# Environment variable reference

Single source of truth for every env var a user or operator sets on stow.
Variables a stow process wires for its own children appear where they
explain the wrapper's behavior; the rest of the internal plumbing
(`STOW_RUSTC_EXTRA_ARGS_FILE`) and the sandbox test hooks are omitted on
purpose. Each row lists the component(s) that read the variable, the
default, and the purpose.

## CLI / wrapper (`stow`, `cargo-stow`)

| Variable | Default | Purpose |
|---|---|---|
| `STOW_EDGE_URL` | `https://stow.waterui.dev` | HTTPS URL of the edge worker — the CLI streams bundles from `/api/v1/bundles/{rustc_version}/{digest}` (the byte path) and posts `/api/v1/admissions` (miss minting) and `/api/v1/enqueue` (PoW redemption) to it. Falls back to `edge_url` in `~/Library/Application Support/stow/config.toml` (macOS) or `~/.config/stow/config.toml` (Linux), then to the production edge. |
| `STOW_REGISTRY_BASE_URL` | `https://ghcr.io` | OCI registry root (`scheme://host[:port]`) the CLI pulls signed index slices from — the pull appends `/v2/water-rs/stow-cache-<rustc>` for the rustc's package (bundle bytes stream through the edge). Override for mock-registry runs; `registry_base_url` in the config file does the same. |
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
| `STOW_TRACE_FILE` | unset | When set, stow writes a Chrome-format trace holding every span and event of stow's own crates whatever `RUST_LOG` is — that variable selects only what the terminal prints. Open in chrome://tracing or perfetto.dev. |
| `STOW_TRACE_WRAPPED_COMPILERS` | unset | When set, the wrapper emits tracing for every wrapped `rustc` / `cc` invocation (verbose). |
| `STOW_IDENTITY_TRACE` | unset | Directory the wrapper writes one JSON identity record per `rustc` invocation into (`IdentityTraceRecord`: the parsed inputs — target, rustc, emit, crate types, profile, features, dependency `c_metadata` chain — plus the computed compile key and `c_metadata`). The answer to "why did this unit miss" — diff the record for the missing unit against the index row it should have hit. Inert when unset. |
| `STOW_ENABLE_SEMANTIC_FALLBACK` | wired by parent `stow check` | When `1`, the per-rustc wrapper falls back to a semver-relaxed lookup in the cached index slice after an exact-key miss. |
| `STOW_EXPANDED_GRAPH_PATH` | wired by parent `stow build`/`check`/`test` | Path to the build's unit-graph file — a JSON `{"consumer_spelled_target": bool, "nodes": [{"crate_name", "version", "host_side", "features"}]}` written atomically in the build's scratch directory (a `stow-build-*` directory under the system temp directory, removed when the build ends) — the build's unit graph as a per-side node table (each lib node's cargo-resolved feature set, plus whether the graph's cargo invocation spelled `--target`). The wrapper resolves each compiled unit's semantic identity against it; the argv `--cfg feature` scan is compile-key evidence only. A set path whose file is missing or malformed fails the invocation loudly; unset carries no table. |
| `__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS` | `nightly`, set on the `--unit-graph` query child only | Cargo's own channel override: makes the wrapped cargo accept `-Z unstable-options` on a stable toolchain while rustc — which never reads it — keeps answering probes as stable. Set only when the channel is stable and the user has no `RUSTC_BOOTSTRAP` of their own. |
| `STOW_PREFETCH_ARTIFACTS_PATH` | wired by parent `stow build`/`check`/`test` | Path to the build's prefetch ledger file — a JSON `Vec<PrefetchArtifactRow>` written atomically in the build's scratch directory: (crate, c_metadata, bundle_digest) triples to stream through the edge byte path — each checked against its `bundle_digest` — before any rustc invocation. A set path whose file is missing or malformed fails the invocation loudly; unset carries no ledger. |
| `STOW_CACHE_POLICY_PATH` | wired by parent | Directory of `allow/<target>/<c_metadata>` marker files. The wrapper only consults the public cache for invocations with a marker; the parent `stow check` writes the markers from the local index analysis. |
| `STOW_SUPERVISOR_ENDPOINT` / `STOW_SUPERVISOR_TOKEN` / `STOW_SUPERVISOR_BINARY` | wired by parent `stow check`/`build`/`test` | Endpoint (`unix:<path>` or `tcp:<port>`), bearer token, and binary identity (`<len>:<modified-nanos>` of the executable the shims resolve to) of the supervising run the wrapper delegates each invocation to. An endpoint that is set but unusable fails the build, as does a binary identity missing or different from the wrapper's own — the stow binary was replaced while the build ran; unset means standalone mode, where the wrapper decides in-process. |
| `STOW_SERVE_MAP_FILE` | wired by parent `stow build`/`check`/`test` | Path to the build's serve map file, a JSON `{"target": [[name, version], ...], "host": [[name, version], ...], "pending": bool}` written atomically in the build's scratch directory — the canonical `(crate, version)` pairs the build's index slices and local cache could serve, per side of the unit graph (`"*"` version = any semver-compatible version). The rustc facade reads it before starting its runtime: a unit the map does not cover compiles immediately, reporting over one-way supervisor frames; a covered unit — or any invocation with no map — takes the plan round trip. `pending: true` means the map was written from the cached slices alone while the fresh index fetch was still running: a facade whose crate the map names at some version or side but whose unit it does not cover then sends one `AwaitServeMap` frame over the build's supervisor transport (unix socket or loopback TCP — the same transport the Windows build uses) and the supervisor answers once the build's background analysis has written the final map, or at once when it already has; the read carries a bounded timeout and a dead driver ends the wait by dropping the connection, so the facade always decides on the map it then finds. A facade whose crate the map never covered — at any version, on either side — does not wait on the fetch at all. The build's background analysis rewrites the file mid-build once the full graph resolves; an absent file reads as an empty map. |
| `STOW_WRAPPER_PATH` | unset | Overrides the runtime wrapper binary `stow setup` points the cargo config at (defaults to the current executable). |
| `CC` / `CXX`, and the `cc` crate's scoped forms (`CC_<triple>`, `CXX_<triple>`, `TARGET_CC`/`HOST_CC`, `TARGET_CXX`/`HOST_CXX`) | platform compiler | The C/C++ toolchain the caller configured for a target, in the precedence order the `cc` crate reads it. `stow setup` consults all of them; a configured toolchain is recorded as `STOW_REAL_CC`/`STOW_REAL_CXX`, and setup writes the shims under `CC_<host triple>`/`CXX_<host triple>` so only the host target routes through stow — other targets keep the compiler cc-rs would pick. |
| `STOW_REAL_CC` / `STOW_REAL_CXX` | unset | Written by `stow setup` (and by `stow build`/`check`/`test` for their children) only when a toolchain was configured — the executable the `stow-cc`/`stow-cxx` shims then exec. When unset, a shim resolves the platform's compiler per invocation the way the `cc` crate does: on an msvc target, `find_msvc_tools` for `cl.exe` with that toolchain's environment applied to the child — nothing is persisted, so a Visual Studio update never strands the wiring. |
| `TARGET` | set by cargo | The build target the `stow-cc`/`stow-cxx` shims resolve their compiler for — how an x64→aarch64 cross build picks the aarch64 `cl.exe`. Build scripts get it from cargo; outside one, a shim assumes the host target. |
| `CMAKE_C_COMPILER_LAUNCHER` / `CMAKE_CXX_COMPILER_LAUNCHER` | set by `stow setup` | The `stow-cc-launcher` shim, wired in the global `[env]` table. CMake has no target-scoped form of these, so they stay bare; the launcher wraps whichever compiler CMake picks and runs it through the same cache path as the `CC`/`CXX` shims. |
| `PATH` | inherited | Read — never written — by stow's link resolution: it decides where a bare linker or driver name and `ld.mold` resolve, and it is digested into the cached resolution's key so a different `PATH` re-resolves instead of serving the witnesses another search order produced. |
| `RUSTFLAGS` / `CARGO_ENCODED_RUSTFLAGS` / `CARGO_BUILD_RUSTFLAGS` / `CARGO_TARGET_<triple>_RUSTFLAGS`, `CARGO_TARGET_<triple>_LINKER` | unset | Cargo's own flag and linker env sources — read, never written, by stow's linker resolution when it decides whether the configuration already selects a reachable mold. |
| `RUSTC` / `CARGO_BUILD_RUSTC`, `RUSTC_WRAPPER` / `CARGO_BUILD_RUSTC_WRAPPER` / `RUSTC_WORKSPACE_WRAPPER` / `CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER`, `RUSTC_BOOTSTRAP`, `CARGO_BUILD_TARGET` | unset | The rest of the cargo environment the link resolution digests into its cache key: `RUSTC`/`CARGO_BUILD_RUSTC` name the rustc whose `-vV` the key carries and the cfg evaluation runs — the evaluation pins `build.rustc` to the build rustc, so it never consults the rustc beside `$CARGO` — and the wrapper and bootstrap vars ride along so a changed toolchain or wrapper re-resolves rather than serving a stale answer. |
| `COMPILER_PATH` | set by `stow setup` | Written into the global `[env]` table on Linux — the managed mold install's `bin` dir, where the compiler driver finds `ld.mold`. Deliberately an env var, not a rustflag, so it never enters the compile key. |
| `CARGO_HOME` | unset | Cargo's own home — `stow setup` writes its wrapper wiring into `$CARGO_HOME/config.toml`, resolving it exactly as cargo does (the variable, else `~/.cargo`). |
| `RUSTUP_HOME` | unset | Rustup's home — under `--isolation strict` or `offline`, stow grants the toolchain tree it names (else `~/.rustup` when that exists) and re-exports it inside the sandbox so the rustup proxies never fall back to a home they cannot write. |
| `CC` / `CXX` / `AR` / `RANLIB` / `LD`, the `CFLAGS` / `CXXFLAGS` / `CPPFLAGS` / `LDFLAGS` family, `SDKROOT` / `DEVELOPER_DIR`, the MSVC developer environment (`LIB`, `INCLUDE`, `VCINSTALLDIR`, `VCToolsInstallDir`, `WindowsSdkDir`, `WindowsSdkBinPath`, `WindowsSdkVerBinPath`, `WindowsSDKVersion`, `WindowsSDKLibVersion`, `UniversalCRTSdkDir`, `UCRTVersion`), the Android roots (`ANDROID_HOME`, `ANDROID_SDK_ROOT`, `ANDROID_NDK`, `ANDROID_NDK_HOME`, `ANDROID_NDK_ROOT`, `ANDROID_NDK_LATEST_HOME`), `PKG_CONFIG*` / `CMAKE_*` / `LC_*` / `CARGO_TARGET_*` / `CARGO_TERM_*` / `CARGO_BUILD_*` / `RUSTUP_*` | unset | Under `--isolation strict` or `offline`, the environment allowlist (`protect` passes every host variable except credential variables — names containing `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`, `PASSPHRASE`, `CREDENTIAL`, `API_KEY`, `APIKEY`, `ACCESS_KEY` or `PRIVATE_KEY`, plus `SSH_AUTH_SOCK`, `SSH_AGENT_PID`, `GPG_AGENT_INFO` and `DOCKER_AUTH_CONFIG`): toolchain variables are passed into the sandboxed build verbatim, and a variable naming an executable file (`CARGO_TARGET_<triple>_LINKER`, `CC_<triple>` and friends) or a toolchain root (`SDKROOT`, `DEVELOPER_DIR`, the Android roots) additionally grants read+execute on the directory it names. `CARGO_TARGET_DIR`, `CARGO_HOME` and `RUSTUP_HOME` are never passed through — the sandbox resolves and sets them itself. |
| `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` (any case) | unset | Under every sandboxed level these are filtered out: heel publishes its own in-process proxy as `HTTP_PROXY`/`HTTPS_PROXY` inside the sandbox so every outbound connection goes through the declared network policy. |
| `STOW_CLI_GITHUB_TOKEN` | falls back to `GITHUB_TOKEN`, then `GH_TOKEN` | GitHub token `stow update` sends with its release lookups — only useful against rate limits or a private mirror. |
| `STOW_NO_ANALYTICS` | unset | When `1`, every edge request carries `x-stow-no-analytics: 1` and the edge writes no usage-statistics point and computes no install hash for it. The CLI also sends no daily build report at all. See [`PRIVACY.md`](../PRIVACY.md). |
| `CI` | unset (set by CI providers) | When present (any value), every edge request carries `x-stow-ci: 1` so the usage statistics can split CI from local builds. Standard convention — GitHub Actions, GitLab CI and friends set it. See [`PRIVACY.md`](../PRIVACY.md). |
| `RUST_LOG` | unset (defaults to `warn`) | Standard tracing-env-filter directive (e.g., `stow_cli=debug,info`). Without it, only `warn`/`error` events print — one per condition per build; per-unit lookup detail and per-attempt retries sit at `debug`. |

`stow stats` prints this install's own cache counters (`--json` for
JSON) and sends nothing.

## stow-admin

| Variable | Default | Purpose |
|---|---|---|
| `STOW_EDGE_URL` | _required for the edge-backed commands_ | Edge base URL the admin's trusted calls go to: scheduler task submits (including `request resolve`'s `/api/v1/scheduler/requests/{id}/outcome` post), `scheduler demand-feed` (the `/api/v1/admin/scheduler/demand-feed/*` input lane — see the demand-feed runbook below), `dispatch-freeze status\|engage\|clear` (the `/api/v1/admin/dispatch-freeze` switch), `dispatch-cap status\|set` (the `/api/v1/admin/dispatch-cap` caps) and `index report`/`index reconcile` (`/api/v1/admin/index/published`, and `reconcile` reads `/api/v1/admin/status`). Its host is also the `http.host` term `maintenance ensure`/`on`/`off` write into the zone's WAF rules. A command that dispatches `operations.yml` (every operator mutation run outside Actions — see `DEPLOYMENT.md`'s *Operator mutations*) requires it set and not loopback, but only as a guard: the workflow acts on the repository variable `STOW_EDGE_URL` whatever this says. `index export`/`publish` never read it — they run against GHCR only. `preheat manual` and the preheat lanes (`top-binaries`, `binary`, `missed`, `projects submit`, `plan`) read it only under `--yes`, when they submit: a plan-only run needs neither it nor an edge credential. |
| `STOW_EDGE_VERSION_OVERRIDE` | _optional_ | Verbatim `Cloudflare-Workers-Version-Overrides` header value (e.g. `stow-edge="<version-id>"`) pinned onto every edge call — `deploy-edge.yml` sets it so trusted calls run on the uploaded candidate before traffic shifts. |
| `GH_TOKEN` / `GITHUB_TOKEN` | edge: the `stow-admin login` token; GitHub REST: `gh auth token` | GitHub credential for the GitHub REST calls (`runs`, `builds`, `cache`, `preheat projects generate`), and when set and non-empty it replaces the `stow-admin login` token as the operator credential: it authenticates the edge's read routes and dispatches `operations.yml` for the mutating commands, so its owner needs push access to `water-rs/stow` and Actions read and write. A value that is a JWT (`eyJ…`, three segments) is an Actions OIDC identity instead — the mock stack's `stow-mock-registry oidc-token` — and makes the mutating commands call the edge directly rather than dispatch. `stow-admin` never forwards `gh auth token` to the edge. |
| `CF_ACCOUNT_ID` | _required for `preheat missed` and `watchdog`_ | Cloudflare account ID the Analytics Engine SQL API URL is built from. |
| `CF_ZONE_ID` | _required for `maintenance` and `watchdog`_ | Cloudflare zone ID of `waterui.dev`, whose `http_request_firewall_custom` phase holds the three `stow maintenance:` WAF rules. In CI it is the `CF_ZONE_ID` repository variable; an operator never sets it, since `operations.yml` runs these commands. |
| `CF_ANALYTICS_TOKEN` | _required for `preheat missed`_ | Cloudflare API token with `Account Analytics: Read`, used to query the `stow_cache_misses` dataset. In CI it comes from the `CF_ANALYTICS_TOKEN` repository secret (see `DEPLOYMENT.md`); `operations.yml` hands it to `preheat missed` alone. |
| `STOW_CF_ANALYTICS_SQL_BASE` | unset | **Mock/test-only.** Overrides the Analytics Engine SQL API base URL (`https://api.cloudflare.com/client/v4`) that `preheat missed` and the watchdog's `edge.do.overloaded` collector post their `stow_cache_misses` queries to, so the e2e can point those lanes at a loopback fixture. Production never sets it — the constant is the only live endpoint — and like `STOW_STATS_SQL_URL` the URL must stay loopback-pinned: the Cloudflare API token rides in the `Authorization` header, so a non-loopback URL would exfiltrate it. |
| `STOW_WATCHDOG_HOURLY_ALERT_PERCENTS` | `200,300` | Comma-separated percents of the hourly pace (a billed dimension's monthly allowance over the hours of the current UTC month) at which `watchdog` raises an alert on the last hour's usage. Alert only — the trips judge the month-to-date total against 80% of the allowance. Unset or empty is the default; a value that is not a list of numbers fails the run. In CI it is the `STOW_WATCHDOG_HOURLY_ALERT_PERCENTS` repository variable, passed into `watchdog.yml` and `operations.yml`. |
| `CLOUDFLARE_API_TOKEN` | _required for `watchdog`, `deploy verdict` and `maintenance`_ | Cloudflare API token. The watchdog queries the GraphQL analytics and Analytics Engine APIs with it and sends the alert mail through the Email Sending REST API (`POST /accounts/{id}/email/sending/send`); `deploy verdict` queries the GraphQL Analytics API (`workersInvocationsAdaptive`, `durableObjectsInvocationsAdaptiveGroups`, `durableObjectsPeriodicGroups`); `maintenance` toggles the zone's WAF maintenance rules. Needs `Account Analytics:Read`, Email Sending and `Zone WAF:Edit` on `waterui.dev`. In CI it is the `CLOUDFLARE_API_TOKEN` repository secret — see `DEPLOYMENT.md`; no operator holds it, since `operations.yml` runs `maintenance` and `watchdog`. |
| `STOW_OIDC_AUDIENCE` | _required in Actions_ | `aud` the admin requests when it mints a GitHub Actions OIDC token for an edge call; must equal the edge's `STOW_OIDC_AUDIENCE` var. Set from `vars.STOW_OIDC_AUDIENCE` in the workflow. |
| `ACTIONS_ID_TOKEN_REQUEST_URL` / `ACTIONS_ID_TOKEN_REQUEST_TOKEN` | injected by Actions | Endpoint + bearer the runtime exposes for OIDC mints; the admin reads both to mint a fresh token per edge call. Absent them (outside Actions), the admin uses `GH_TOKEN`/`GITHUB_TOKEN`, else the `stow-admin login` token. |
| `STOW_REGISTRY_BASE_URL` | production GHCR | OCI registry root (`scheme://host[:port]`, no path — the per-rustc repository is appended by code) `index export`/`preheat manual`/`preheat plan` pull records, bundles and published slices from — anonymously, signatures verified. Override for mock-registry runs. |
| `STOW_MOCK_PUBLIC_KEY_PATH` | unset | Mock cosign key `index export`/`preheat manual`/`preheat plan` verify records and index slices against under a mock registry — the `mock-verify` code path, never production. |
| `STOW_CACHE_DIR` | `stow` under the platform cache directory (`~/Library/Caches/stow` on macOS, `$XDG_CACHE_HOME/stow` or `~/.cache/stow` on Linux, `%LOCALAPPDATA%\stow` on Windows) | Fulcio/Rekor trust material cache for `index export`, `preheat manual` and `preheat plan` signature verification. |
| `RUST_LOG` | unset (defaults to `info,stow_oci::client=debug`) | Standard tracing-env-filter directive. The default keeps `stow_oci`'s per-attempt registry retry lines — `debug` for end users (stow#633), operator-visible here. |
| `STOW_RESOLVE_CARGO_HOME` | fresh per-process tempdir | Root every resolve `CARGO_HOME` the process creates lives under: the lane's own resolver at `<root>/main`, each resolve worker's at `<root>/worker-N`. The preheat lanes and `preheat manual` read it through the resolve pool; `production-wave.sh` sets it per lane (`<root>/<NN>-<lane>`) and `preheat-admin.yml` and `release-gate.yml`'s `Production wave` job point it at their `actions/cache`-restored directories so the sparse crates.io index and `.crate` bodies stay warm across runs. Unset keeps the temporary root — the lanes' historical isolation. |
| `STOW_RESOLVE_CONCURRENCY` | `4` | Worker count a lane fans its resolves across; each worker owns its own `CARGO_HOME` shard under the resolve root. The knob the stow#884 concurrency measurements were taken through. |

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
target, and `index report` POSTs each slice's membership to the
scheduler.
`--full` ignores the folded sets and re-pulls everything — for the first
publish of a new rustc and for disaster recovery.

`stow-admin preheat manual --crates|--projects <file> --rustc-version <v>
[--targets a,b] [--priority 30] [--yes]` is the operator-driven wave
(stow#880): it resolves the graph in-process for every CI target — under
`--yes`, outside Actions, inside the `operations.yml` run it dispatches,
which carries the files' contents (`--dirs` is refused there) — and
submits one dependency tree per source to the scheduler's operations
entry point at the caller's `--priority` — the same operand
`stow-admin submit` takes — through
`/api/v1/scheduler/tasks/submit`. The scheduler owns dispatch, rerun and
index publishing from there; a `--projects` repository that fails to
resolve is reported after the wave submits the rest, and the run exits
non-zero naming it, while a `--crates` or `--dirs` failure still
aborts before submission. Without `--yes` the plan prints and nothing
is submitted.

## stow-build (CI runner)

The runner has three subcommands. `stow-build build --output-dir <dir>` is
the untrusted stage (compiles the task's crate, writes task, plan and blobs
into `<dir>`); `stow-build publish --input-dir <dir>` is the trusted stage
(validates `<dir>`, then pushes and signs the bundle plus the task's
records artifact into GHCR — GitHub's `workflow_run` webhook reports
the run, so publish never calls the edge); `stow-build serve --listen
<host:port>` is the dev-only local dispatch endpoint. Both stages read the
task from the dispatch event file `GITHUB_EVENT_PATH` names
(`.inputs.task`, a JSON `BuildTaskPayload`) — the dispatched
`build-crate.yml` run's `workflow_dispatch`.

| Variable | Stage | Purpose |
|---|---|---|
| `GITHUB_EVENT_PATH` | build, publish | Actions dispatch event file holding the task (`inputs.task`, a JSON `BuildTaskPayload`). The runner injects it into every job. Required. |
| `STOW_BUILD_WORKSPACE_ROOT` | build | Pre-existing path to build in instead of a tempdir. |
| `STOW_BUILD_CARGO_SUBCOMMAND` | build | One of `build` / `check` / `test`. Default `build`. |
| `STOW_BUILD_RUSTC_CAPTURE_DIR` | build (set by the runner for its rustc wrapper) | Per-rustc-invocation capture sink for output snapshots and identity sidecars. |
| `STOW_BUILD_CAPTURE_IPC` | build (set by the runner inside the heel sandbox) | IPC socket the rustc wrapper streams capture records to; the host collector, not the wrapper, owns record persistence. |
| `STOW_BUILD_WRAPPER_CRATE_NAME` | build (set by the runner inside the heel sandbox) | Package name of the generated wrapper package the task crate builds under; the rustc wrapper records its units as observed scaffolding, never publishable artifacts. |
| `STOW_BUILD_MOCK_COMPILE` | build (set by the `Preheat cost` lane's local CI) | `1` makes the capture wrapper answer every compiling rustc invocation with empty outputs at the paths rustc would write, instead of running rustc; probes (`--print`, stdin sources) still run the real compiler. Honoured only by a `stow-build` compiled with the `mock-compile` feature — any other build refuses to start when it is set. See `scripts/preheat-cost.sh`. |
| `STOW_BUILD_MOCK_HOST` | build (set by the runner on the sandboxed phases and unit-graph resolves of a mock-compile build) | The host triple the mock-compile capture wrapper answers as: the host of the runner family the task's target is dispatched to, so one machine builds every CI target's host units as that target's runner would. `rustc -vV` reports it, target-less probes ask rustc about it, and target-less units are keyed and named for it. Required whenever `STOW_BUILD_MOCK_COMPILE=1` reaches the wrapper. |
| `STOW_GLIBC_SYSROOT` | build (set by the Linux build of `build-crate.yml`) | Root of the glibc-2.28 sysroot the Linux build job installs under `$HOME/stow-glibc-2.28` — the heel sandbox grants the whole tree to the untrusted crate build so its compiles and links read the sysroot's headers and libraries. The job's PATH shim dir (`<root>/bin`, canonical driver names carrying `-B`/`--sysroot`) is reached through the `PATH` passthrough; `STOW_GLIBC_SYSROOT` itself rides the toolchain passthrough like every other `CC_*`/`CARGO_TARGET_*` variable. |
| `STOW_SYSTEM_LIBS` | build (set by the Linux build of `build-crate.yml`) | Root of the system-library tree `ci/system-libs/install.sh` extracts from the sha256-locked debs under `$HOME/stow-system-libs` (stow#850) — amd64 and arm64 headers, `.pc` files and libraries the pkg-config, shim, bindgen and CMake lookups are pointed at. The heel sandbox grants read+exec on the whole tree through the toolchain passthrough, like `STOW_GLIBC_SYSROOT`. |
| The toolchain passthrough: `CC` / `CXX` / `AR` / `RANLIB`, `CFLAGS` / `CXXFLAGS` / `CPPFLAGS` / `LDFLAGS`, `SDKROOT` / `DEVELOPER_DIR`, the MSVC developer environment (`LIB`, `INCLUDE`, `VCINSTALLDIR`, `VCToolsInstallDir`, `WindowsSdkDir`, `WindowsSdkBinPath`, `WindowsSdkVerBinPath`, `WindowsSDKVersion`, `WindowsSDKLibVersion`, `UniversalCRTSdkDir`, `UCRTVersion`), `CMAKE_PREFIX_PATH`, and every name beginning `CARGO_TARGET_` (except `CARGO_TARGET_DIR`), `CC_`, `CXX_`, `AR_`, `RANLIB_`, `CFLAGS_`, `CXXFLAGS_`, `CPPFLAGS_`, `LDFLAGS_`, `PKG_CONFIG_` or `BINDGEN_EXTRA_CLANG_ARGS` | build (set by the job) | Handed unchanged into the sandboxed crate build; the Android SDK/NDK roots (`ANDROID_HOME`, `ANDROID_SDK_ROOT`, `ANDROID_NDK`, `ANDROID_NDK_HOME`, `ANDROID_NDK_ROOT`, `ANDROID_NDK_LATEST_HOME`) pass only to an Android task. The aarch64 Linux build sets `PKG_CONFIG_aarch64_unknown_linux_gnu=aarch64-linux-gnu-pkg-config`, per target so a build script compiling for the host keeps the native one; the name resolves to the sysroot-written wrapper whose `PKG_CONFIG_LIBDIR` is the arm64 half of `STOW_SYSTEM_LIBS` plus the image's `/usr/share/pkgconfig`. `env.sh` also exports, per architecture half the root carries, `PKG_CONFIG_PATH_x86_64_unknown_linux_gnu` and `BINDGEN_EXTRA_CLANG_ARGS_<target>` (the root's `-isystem` include dirs), plus `CMAKE_PREFIX_PATH=<root>/usr`. |
| `GHCR_USERNAME` / `GHCR_TOKEN` | publish | Credentials for `oci-client` to push bundles to GHCR. Required. |
| `GITHUB_RUN_ID` / `GITHUB_RUN_ATTEMPT` | publish | Actions run identity the records artifact's per-build tag carries — `records-<rustc>-<task_id hash>-<run_id>-<run_attempt>`. Both must be numeric; the Actions runner injects them into every job's environment. Required. |
| `STOW_CACHE_DIR` | publish, records-exist | Fulcio/Rekor trust material cache the records-marker signature verification writes through to. Default is `stow` under the platform cache directory (`~/Library/Caches/stow` on macOS, `$XDG_CACHE_HOME/stow` or `~/.cache/stow` on Linux, `%LOCALAPPDATA%\stow` on Windows) — `HOME` is never read, which a Windows runner has none of; the variable overrides it. |
| `STOW_MOCK_PUBLIC_KEY_PATH` | publish, records-exist | Mock cosign key the records-marker verification trusts under a mock registry — honoured only by a `stow-build` built with the `mock-verify` feature; a build without it errors when the variable is set. |
| `STOW_EDGE_URL` | serve | Edge base URL the local server's `workflow_run` webhook POSTs to. Required. |
| `STOW_GITHUB_WEBHOOK_SECRET` | serve | HMAC key the webhook signature is computed with — the same value the edge verifies `X-Hub-Signature-256` against. Required. |
| `GITHUB_APP_SLUG` | serve | The App slug the server renders into `triggering_actor.login` (`<slug>[bot]`) on the `workflow_run` deliveries of every run it was dispatched — the value the edge's `GITHUB_APP_SLUG` binding names, so the webhook reads its own runs as dispatched by the App. Required. |
| `STOW_NEWRELEASES_WEBHOOK_SECRET` | serve | Signing secret of the newreleases.io webhook on `rust-lang/rust` releases (stow#880) — the value the subscription's *Key* shows, which the edge verifies `X-Newreleases-Signature` (hex HMAC-SHA256 of `<X-Newreleases-Timestamp>.<body>`, timestamp inside ±300 s) against on `POST /api/v1/newreleases/release`. Required. |
| `STOW_OIDC_AUDIENCE` | publish (Actions) | `aud` for the edge OIDC token minted when a publish step calls a trusted edge route (the publish's `index report`/`index reconcile`); unused when the run only pushes GHCR artifacts. |
| `STOW_MOCK_PRIVATE_KEY_PATH` / `STOW_MOCK_REGISTRY_ROOT` | serve | Mock cosign signing key and mock registry root the local dispatcher populates. Required. |
| `STOW_LOCAL_CI_STUB` | serve | **Mock/test-only.** When set (any value), the local CI server short-circuits each task's build and publish work — the dispatch POST the budget probe and the launch-load run measure stays real, while a stubbed run still pushes the task's (empty) records artifact and completes through the same signed `workflow_run` webhook. |
| `RUST_LOG` | unset (defaults to `info,stow_oci::client=debug`) | Standard tracing-env-filter directive. The default keeps `stow_oci`'s per-attempt registry retry lines — `debug` for end users (stow#633), visible in CI logs here. |

## Local code signing (`admin/build.rs` + `scripts/signing-ld.sh`)

| Variable | Default | Purpose |
|---|---|---|
| `STOW_LOCAL_SIGNING_IDENTITY` | unset | Read by `admin/build.rs` on macOS targets only: set to a code-signing identity name (`stow-admin-local`, created once per machine by `scripts/local-signing-identity.sh`), the build script selects `scripts/signing-ld.sh` as the `stow-admin` binary's linker (`--ld-path`), which re-signs the link's output with that identity instead of keeping the ad-hoc signature `ld` leaves — a stable, certificate-based code requirement the keychain ACL still recognises after the next rebuild, which is what keeps `stow-admin login`'s "Always Allow" valid. Only the `stow-admin` bin target is signed. Unset, the build emits nothing and the link is identical to one without the mechanism; set to an identity `codesign` cannot find, the link fails. See `USAGE.md`'s local code signing section. |

## scripts/preheat-cost.sh

The `Preheat cost` lane (stow#773): a whole preheat wave and the daily
resubmit driven through the mock stack, priced in the scheduler's
billed rows. `docs/MOCK.md` describes the run. The script stops unless a GitHub
credential is in the environment (`GH_TOKEN` / `GITHUB_TOKEN`, else `gh
auth token`); every edge call it makes carries a token from
`stow-mock-registry oidc-token`.

| Variable | Default | Purpose |
|---|---|---|
| `STOW_PREHEAT_COST_WORK_DIR` | fresh `mktemp -d` | Work dir for keys, registry, edge state, logs, ledger snapshots and `preheat-cost-report.json`. Must be empty. |
| `STOW_PREHEAT_COST_LIMIT` | `100` | `--limit` of `preheat top-binaries` — the production `preheat-admin.yml` value. |
| `STOW_PREHEAT_COST_PROJECTS` | every listed repository | `preheat projects submit --limit`: resolve only the first N repositories of `preheat/projects.toml`. |
| `STOW_PREHEAT_COST_TARGETS` | every `CI_TARGET_TRIPLES` entry | Comma-separated `--targets` for every lane. |
| `STOW_PREHEAT_COST_MAX_JOBS` / `STOW_PREHEAT_COST_MAX_MACOS_JOBS` | `45` / `11` | The scheduler's dispatch caps for the run — `edge/Skyzen.toml`'s production values, replacing the mock manifest's. |
| `STOW_PREHEAT_COST_DEADLINE` | `21600` | Seconds the wave (and, separately, the resubmit) may run before the script fails. |
| `STOW_PREHEAT_COST_EDGE_RSS_MB` | `1200` | Restart the `wrangler dev` edge at an idle point once its process tree passes this resident size; the probe ledger is read on both sides of the restart. |
| `STOW_E2E_TOOLCHAIN` / `STOW_E2E_READY_DEADLINE` | `stable` / `600` | The rustup toolchain the run builds for, and how long each service may take to come up — shared with `scripts/mock-e2e.sh`. |

## scripts/production-wave.sh

The release gate's `Production wave` job: the three production preheat
lanes resolved plan-only, concurrently, to count the production wave's
distinct nodes for the monthly projection. No edge, mock stack or edge
credential is involved (`docs/MOCK.md`).

| Variable | Default | Purpose |
|---|---|---|
| `STOW_PRODUCTION_WAVE_WORK_DIR` | fresh `mktemp -d` | Work dir for `logs/`, `lanes/<NN>-<lane>/` and `production-wave.json`. Must be empty. |
| `STOW_PRODUCTION_WAVE_LIMIT` | the `limit` input's default in `.github/workflows/preheat-admin.yml` | `--limit` of `preheat top-binaries`. |
| `STOW_PRODUCTION_WAVE_TARGETS` | the `targets` input's default in `.github/workflows/preheat-admin.yml` | Comma-separated `--targets` of every lane. |
| `STOW_PRODUCTION_WAVE_DEADLINE` | `3300` | Seconds each lane may run before it is killed; the count then refuses the lane. |
| `STOW_RESOLVE_CARGO_HOME` | `$WORK_DIR/resolve-cargo` | The shared resolve root the script exports to each lane as `<root>/<NN>-<lane>` — separate per lane because the lanes run concurrently and a worker's resolve holds cargo's exclusive package-cache lock. Point it at a cache-restored directory so warm runs skip the cold index/`.crate` fetch. |
| `STOW_E2E_TOOLCHAIN` | `stable` | The rustup toolchain whose version the lanes resolve for (`RUSTUP_TOOLCHAIN`). |

## scripts/mock-e2e.sh

The mock end-to-end run (`docs/MOCK.md`). Every variable is optional
except a GitHub credential (`GH_TOKEN` / `GITHUB_TOKEN`, else `gh
auth token`), which the script uses for its read-route calls against the
mock's push check; every mutating call carries a token from
`stow-mock-registry oidc-token`.

| Variable | Default | Purpose |
|---|---|---|
| `STOW_E2E_WORK_DIR` | fresh `mktemp -d` under `TMPDIR` | Work directory: keys, mock registry, edge state, stow cache, `logs/`, the local-CI dispatch tree. Must be empty when given. |
| `STOW_E2E_TOOLCHAIN` | `stable` | rustup toolchain the run builds with (`RUSTUP_TOOLCHAIN`); must be a release — the build stage re-pins the task's rustc version as a toolchain name. |
| `STOW_E2E_READY_DEADLINE` | `600` | Seconds to wait for each service to listen. |
| `STOW_E2E_TASK_DEADLINE` | `1200` | Seconds to wait for a scheduler graph to drain. |
| `STOW_E2E_EDGE_PORT` | `8788` | Port `wrangler dev` binds the edge on. |
| `STOW_E2E_INSPECTOR_PORT` | `9229` | Port the workerd inspector binds. |
| `STOW_E2E_REGISTRY_PORT` | `28123` | Port `stow-mock-registry serve` binds; the edge bundle's `GHCR_BASE_URL` / `STOW_GITHUB_API_URL` / `STOW_STATS_SQL_URL` are rendered to match at `skyzen build` time. |
| `STOW_E2E_LOCAL_CI_PORT` | `28124` | Port `stow-build serve` binds; the edge bundle's `STOW_LOCAL_CI_URL` is rendered to match at `skyzen build` time. |

## stow-mock-registry

| Variable | Default | Purpose |
|---|---|---|
| `RUST_LOG` | unset | Standard tracing filter. |

The mock registry is a one-shot CLI; everything else is positional args.
`stow-mock-registry oidc-token --workflow <file> [--ref <ref>] [--actor <login>]
[--lifetime-secs <n>]` prints a mock-issued Actions OIDC token for one
workflow run (`docs/MOCK.md`).

## Forced-eviction check (`scripts/eviction-check.sh`)

Runs on the mock stack (`docs/MOCK.md`); every variable is optional, and
no GitHub credential is needed (its edge calls carry a token from
`stow-mock-registry oidc-token`).

| Variable | Default | Purpose |
|---|---|---|
| `STOW_EVICTION_WORK_DIR` | fresh `mktemp -d` under `TMPDIR` | Work directory: keys, mock registry, edge state and `logs/`. |
| `STOW_EVICTION_ROWS` | `10000` | Fixture queue rows; the smallest shape whose pending set clears its dependency gates. |
| `STOW_EVICTION_READY` | `240` | Seconds to wait for each service to listen. |

## Deploy DO workload (`scripts/deploy-do-workload.sh`)

`deploy-edge.yml` runs it on each side of the promoted verdict (see
`DEPLOYMENT.md`); every variable is required.

| Variable | Default | Purpose |
|---|---|---|
| `STOW_EDGE_URL` | — | Edge base URL the workload requests `/api/v1/scheduler/status` from. |
| `STOW_DO_WORKLOAD_RPS` | — | Requests a second, on a fixed schedule. |
| `STOW_DO_WORKLOAD_MINUTES` | — | Whole minutes the measured window lasts. |
| `GITHUB_OUTPUT` | — | File the window bounds `do_window_from`/`do_window_to` are appended to. |
| `GITHUB_RUN_ID` / `GITHUB_RUN_ATTEMPT` | — | Part of each probe's unique query string. |

## Traffic-cost test (`scripts/traffic-cost.sh`)

The release gate's `Traffic cost` job runs this script on the mock stack
(`docs/MOCK.md`). Every variable is optional, and no GitHub credential
is needed: its edge calls carry a token from `stow-mock-registry
oidc-token`.

| Variable | Default | Purpose |
|---|---|---|
| `STOW_TRAFFIC_WORK_DIR` | fresh `mktemp -d` under `TMPDIR` | Work directory: keys, mock registry, edge state, `logs/` and `reports/`. |
| `STOW_E2E_TOOLCHAIN` | `stable` | rustup toolchain the script builds with (`RUSTUP_TOOLCHAIN`). |
| `STOW_E2E_READY_DEADLINE` | `600` | Seconds to wait for each service to listen. |
| `STOW_TRAFFIC_SIZES` | `100000 480000` | The two fixture sizes, small then large, the budget pass measures; a drive whose rows grow by more than 10% + 50 between them fails. The CPU pass, the peak drive and the post-load pass run on the small one. |
| `STOW_TRAFFIC_DURATION_SECS` | `1800` | Seconds of peak-rate drive. |
| `STOW_TRAFFIC_SEGMENTS` | `4` | Segments the drive runs in; the edge restarts between them to bound `wrangler dev`'s per-request memory retention. |
| `STOW_TRAFFIC_RATE_SCALE` | `1.0` | Multiplier over the launch model's peak rates. |
| `STOW_TRAFFIC_RUSTC` | `1.85.0` | rustc version the lanes request and the index slice is published under. |
| `STOW_TRAFFIC_EDGE_PORT` | `8788` | Port `wrangler dev` binds the edge on. |
| `STOW_TRAFFIC_INSPECTOR_PORT` | `9230` | Port the workerd inspector binds — the CPU pass samples it through DevTools. |
| `STOW_TRAFFIC_REGISTRY_PORT` | `28123` | Port `stow-mock-registry serve` binds; the edge bundle's `GHCR_BASE_URL` / `STOW_GITHUB_API_URL` / `STOW_STATS_SQL_URL` are rendered to match at `skyzen build` time. |
| `STOW_TRAFFIC_LOCAL_CI_PORT` | `28124` | Port `stow-build serve` binds; the edge bundle's `STOW_LOCAL_CI_URL` is rendered to match at `skyzen build` time. |

## edge worker (Cloudflare bindings, set in `wrangler.toml`/`Skyzen.toml`)

| Binding | Default | Purpose |
|---|---|---|
| `STOW_ANALYTICS` | _required_ (Analytics Engine binding) | `stow_cache_misses` dataset — every cache miss is one data point here, so demand analytics spend no row writes. |
| `STOW_STATS` | _required_ (Analytics Engine binding) | `stow_events` dataset — `hit` points on uncached bundle fetches and `build` points on accepted `POST /api/v1/build-report` reports (stow#889). |
| `CF_ACCOUNT_ID` | _required_ (var) | Cloudflare account id the Analytics Engine SQL API is queried under for `GET /api/v1/stats`. |
| `CF_ANALYTICS_TOKEN` | _required_ (secret) | API token with Analytics Engine read on the account — the `Authorization: Bearer` credential `GET /api/v1/stats` queries with. |
| `STOW_STATS_SALT_SECRET` | _required_ (secret) | Daily install-hash salt — the edge hashes it with the request's IP to count installs per day without storing the IP; rotate to rekey, never published. |
| `SCHEDULER` | _required_ (Durable Object binding) | Build scheduler queue. |
| `GITHUB_REPO` | `water-rs/stow` | Repo every trusted credential must resolve inside (OIDC `repository` claim and the push-permission check), and the repository the scheduler triggers `workflow_dispatch` of `build-crate.yml` on. |
| `STOW_OIDC_AUDIENCE` | _required_ (var) | `aud` the edge pins on Actions OIDC tokens; must equal the repo variable CI requests. |
| `GHCR_BASE_URL` | `https://ghcr.io` | OCI registry root (`scheme://host[:port]`) the edge's bundle byte path pulls from — the request's rustc names the `water-rs/stow-cache-<rustc>` package appended under `/v2/`; a mock deploy points it at `stow-mock-registry serve`. |
| `STOW_MAX_EXPANDED_TASKS` | `4096` | Cap on the size of an expanded transitive graph. |
| `STOW_LOCAL_CI_URL` | unset | When set, the scheduler dispatches to this URL instead of GitHub `workflow_dispatch`. Used by mock fixtures. |
| `STOW_SCHEDULER_BUDGET` | unset | **Mock-only.** When `"1"`, the Durable Object answers the `/budget` and `/budget/seed` probe routes the traffic-cost test (`scripts/traffic-cost.sh`) drives. Set only by `edge/Skyzen.mock.toml`; a test asserts it never appears in `edge/Skyzen.toml`, so the probe cannot reach production. |
| `STOW_STATS_SQL_URL` | unset | **Mock-only.** Overrides the Analytics Engine SQL API base URL the public stats routes post to (`/stats` and friends) — and the edge-side override the demand feed's `analytics_engine/sql` query posts through in the mock deploy. Loopback-pinned — the account's analytics token rides in the `Authorization` header, so a non-loopback URL would exfiltrate it; set only by `edge/Skyzen.mock.toml` (to `stow-mock-registry serve`'s stub) and pinned out of `edge/Skyzen.toml` by the same manifest test as `STOW_LOCAL_CI_URL`. |
| `STOW_GITHUB_API_URL` | unset | **Mock-only.** Origin the trusted lanes' bearer check resolves its GitHub probes under — `GET /user`, `GET /{repo}.git/info/refs?service=git-receive-pack`, and the OIDC `/.well-known/jwks` (the key set of the mock issuer `stow-mock-registry oidc-token` signs with) all build on it, replacing `api.github.com`, `github.com` and `token.actions.githubusercontent.com` with a single mock origin. Required whenever `STOW_LOCAL_CI_URL` is set — a mock deploy that omits it fails worker startup rather than letting the check reach the real GitHub API — and loopback-pinned like `STOW_STATS_SQL_URL`, because the caller's credential rides in `Authorization`. The mock manifests point it at `stow-mock-registry serve`'s GitHub stub (same base as `GHCR_BASE_URL`); production never sets it. |
| `STOW_DISPATCH_MIN_AGE_MINUTES` | `5` | Minimum age (minutes) a task must wait in `pending` before being dispatched, so misses can coalesce. Mock fixtures set `0`. |
| `STOW_MAX_CONCURRENT_JOBS` | `45` | Maximum runner slots in-flight `build-crate.yml` runs may hold at once — one run is one slot — across all runner families. Sized against the org's 60-runner pool, leaving 15 runners for the repo's own CI. Mock fixtures set `3` because miniflare OOMs under parallel complete bursts. `"0"` pauses dispatch: submits keep queueing, nothing is claimed, and the alarm wakes only for stale recovery on builds already in flight — see `DEPLOYMENT.md`'s pause procedure. An operator's `dispatch-cap set` overrides the value at claim time until the next set — the binding is the value in force only until the first one. |
| `STOW_MAX_CONCURRENT_MACOS_JOBS` | `11` | Maximum runner slots in-flight `build-crate.yml` runs may hold on macOS targets (`aarch64-apple-*`). The org has 15 macOS runners; the cap leaves 4 for the repo's own CI, and macOS rows past the cap stay pending until a slot frees. A `dispatch-cap set --macos M` overrides the value the same way. |
| `STOW_STALE_DISPATCH_MINUTES` | `60` | The lease on a claimed task, measured from its claim stamp and renewed each time the scheduler's `status` reconcile (run while work lives, and on every wake) lists the claim's own run `queued` or `in_progress` — a build that outlives the span is not re-dispatched. A claim whose run stops listing returns to pending this many minutes after its last sighting. Past the task's ceiling the run fails, so the ceiling — never the lease — is what ends a task. |
| `STOW_POW_CHALLENGE_SECRET` | _required_ (secret) | HMAC-SHA256 key for the enqueue-admission challenge minted on public cache misses and verified by `POST /api/v1/enqueue`. |
| `STOW_POW_MIN_BITS` | `12` | Floor on enqueue proof-of-work difficulty: minted admissions and redeemed tickets never require fewer bits, even on an empty queue. |
| `STOW_MAX_QUEUE_PENDING` | `2000` | Miss-lane pending-task count (preheat, operations and human work queued on other lanes do not count) at which the miss lane refuses `POST /api/v1/enqueue` with 429 and `Retry-After: 600`. Checked inside the scheduler Durable Object at submit; human-lane and workflow-trusted submits are exempt. |
| `STOW_HUMAN_MAX_CLOSURE` | `150` | Largest single-target uncovered closure a request may need. The admitted value rides the `resolve-request.yml` dispatch; the job's resolve fails a request whose largest uncovered target closure exceeds it, so the record ends `failed` naming the size and the cap. |
| `STOW_HUMAN_DAILY_TASK_BUDGET` | `2000` | Human-lane tasks the scheduler accepts per UTC day. The Durable Object keeps the counter (`human_daily_task_budget` table) and refuses an overspending submit with 429; the edge sets `Retry-After` to seconds until 00:00 UTC. |
| `STOW_MIN_DISPATCH_VALUE` | `0` | Admission floor on a pending node's rank operand — its priority, the term `priority × time waited` multiplies (stow#879): a node claims only while its operand reaches the bound — under-floor work stays queued and listed, never built; the human lane is exempt. A nonnegative i64 decimal string in the operand's centi-units (`100` is the CLI miss's priority); the DO parses it when its settings initialize, so an overflow or negative value surfaces then, not at deploy time. |
| `STOW_FREEZE_WINDOW_MINUTES` | `60` | Trailing window (minutes) the dispatch-freeze trip counts terminal attempt outcomes over (the DO's `attempt_outcome_buckets` counters — one five-minute bucket per target, so the read set is window-bounded whatever the traffic). |
| `STOW_FREEZE_MIN_OUTCOMES` | `50` | Sample floor for the trip: a stream (the fleet aggregate or any single target) must reach this many terminal outcomes in the window before its failure ratio is read — below it nothing trips however bad the ratio. |
| `STOW_FREEZE_FAIL_PERCENT` | `50` | Failure ratio (percent, integer-compared) a sufficiently-sampled stream must reach to freeze dispatch — the trip needs both the floor and the ratio, never either alone. |
| `STOW_COST_BUDGET_MULTIPLIER` | `1.0` | Scales the scheduler DO's daily SQL budget — it self-meters `rowsRead`/`rowsWritten` off every statement's cursor and freezes dispatch the moment the day passes (80% of the monthly Workers Paid allowance / 30 — the stow#883 line's daily share) × this value; `0.5` trips at 40% of the allowance. `edge/Skyzen.mock.toml` inflates it (`10000`) so the budget probe's destructive fixture seeds — millions of billed writes — never trip the freeze; the production value lives in `edge/Skyzen.toml`. |
| `STOW_ALERT_FROM` | `alerts@stow.waterui.dev` | Sender address of the freeze/clear alert emails; must live on a domain onboarded and Enabled under Compute → Email Service → Email Sending (`E_SENDER_NOT_VERIFIED` otherwise). |
| `STOW_ALERT_TO` | `me@lexo.cool` | Recipient of the freeze/clear transition alert emails — should match the binding's `allowed_destination_addresses`. |
| `STOW_ALERT_EMAIL` | _declared in `Skyzen.toml` only_ (`send_email` binding, `remote = true`) | Email Service send binding the alert emails go through — `send({to, from, subject, text, html})`. The mock/local manifests deliberately omit it, so their alert path resolves to `Disabled` and can never reach Cloudflare's sending API. |
| `TURNSTILE_SITE_KEY` | `0x4AAAAAAE8LjhnMsqdVhiSp` | Public site key of the invisible Turnstile widget the request page renders; paired with `TURNSTILE_SECRET_KEY`. Mock fixtures use Cloudflare's always-pass test key `1x00000000000000000000AA`. |
| `TURNSTILE_HOSTNAME` | `stow.waterui.dev` | Hostname the Turnstile widget is registered for; a `POST /api/v1/requests` token whose siteverify report names another host is rejected `hostname-mismatch`. Mock fixtures use `example.com`, the hostname Cloudflare's test keys always report. |
| `TURNSTILE_SECRET_KEY` | _required_ (secret) | Turnstile secret key the worker posts to siteverify for `POST /api/v1/requests` token checks. Never logged or returned in a response. Mock fixtures use the always-pass test secret `1x0000000000000000000000000000000AA`; production deploys source it from the `STOW_TURNSTILE_SECRET_KEY` repository secret. |
| `GITHUB_APP_ID` / `GITHUB_APP_INSTALLATION_ID` | `4985635` / `162649982` | The `stow-ci` GitHub App's ID and its installation ID on `water-rs`. Required when `STOW_LOCAL_CI_URL` is unset. |
| `GITHUB_APP_SLUG` | `stow-ci` | The App's slug — its bot login (`<slug>[bot]`) is the `triggering_actor` a scheduler-dispatched `build-crate.yml` run reports, which is how the webhook tells the scheduler's own runs from operator-dispatched ones (stow#940). Required always, including under `STOW_LOCAL_CI_URL`: the mock CI stamps the mock manifest's value on its dispatches, so the same check applies there. |
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
- Concurrency: the GitHub hourly job plus a fresh manual dispatch or an
  operator's `operations.yml` recovery run are the only callers (a
  re-run of a job is refused at the edge); overlapping invocations contend only on the
  DO's serialized storage — the durable cursor is the arbiter, and a
  second job finding the hour frozen delivers rather than
  re-materializing.
- Ordering: the workflow pulls the signed `stow-admin` binary of the
  merge-queue head of `main`; the command ships with this change so
  ticks fail visibly until a released toolchain carries it — no
  per-hour toolchain build, no new alert cron.