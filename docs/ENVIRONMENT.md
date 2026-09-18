# Environment variable reference

Single source of truth for every env var stow reads. Each row lists the
component(s) that read the variable, the default, and the purpose.

## CLI / wrapper (`stow`, `cargo-stow`)

| Variable | Default | Purpose |
|---|---|---|
| `STOW_EDGE_URL` | `https://stow.waterui.dev` | HTTPS URL of the edge worker. Falls back to `edge_url` in `~/Library/Application Support/stow/config.toml` (macOS) or `~/.config/stow/config.toml` (Linux), then to the production edge. |
| `STOW_VERIFY_MODE` | `github-ci` | `github-ci` enforces fulcio-rooted cosign verification; `mock-key` accepts a single PEM public key for local mock. |
| `STOW_MOCK_PUBLIC_KEY_PATH` | _required when `STOW_VERIFY_MODE=mock-key`_ | PEM path the wrapper trusts when verifying mock OCI bundles. |
| `STOW_CACHE_DIR` | OS-specific (macOS: `~/Library/Caches/stow`) | Where the local artifact cache + state SQLite live. |
| `STOW_ARTIFACT_CACHE_MAX_BYTES` | `21474836480` (20 GiB) | Soft cap on the local artifact cache before stow purges old entries. |
| `STOW_DISABLE_PUBLIC_CACHE` | unset | When set (any value), the wrapper bypasses the public cache for the rest of the cargo run. The parent `stow check` sets this for nightly/beta toolchains. |
| `STOW_PUBLIC_CACHE_RUSTC_VERSION` | unset | Set by the parent `stow check` so the per-rustc wrapper does not reprobe `rustc -vV`. |
| `STOW_PUBLIC_CACHE_TARGET` | unset | Same as above for the target triple. |
| `STOW_CONFIG_BLOB` | unset | JSON-encoded resolved `StowConfig`. The parent `stow check` writes this so each rustc-wrapper child skips re-parsing the user config file. |
| `STOW_CACHED_ARTIFACT_MATERIALIZATION` | `reflink-or-copy` | Set to `symlink` to symlink cached artifacts into the target dir instead of reflinking/copying. APFS clones share storage; symlinks share inodes. |
| `STOW_TRACE_FILE` | unset | When set, stow writes a Chrome-format trace covering every `stow.*` span. Open in chrome://tracing or perfetto.dev. |
| `STOW_TRACE_WRAPPED_COMPILERS` | unset | When set, the wrapper emits tracing for every wrapped `rustc` / `cc` invocation (verbose). |
| `STOW_ENABLE_SEMANTIC_FALLBACK` | wired by parent `stow check` | When `1`, the per-rustc wrapper falls back to the edge's semantic POST after an exact-key miss. |
| `STOW_EXPANDED_GRAPH_JSON` | wired by parent | JSON-encoded transitive `Vec<DependencyGraphEntry>` so the wrapper can validate semantic results match the user's lockfile. |
| `STOW_PREFETCH_ARTIFACTS_JSON` | wired by parent | JSON-encoded `Vec<BatchArtifactRequestEntry>` of (crate, c_metadata) tuples to bulk-fetch before any rustc invocation. |
| `STOW_PREFETCH_DEADLINE_SECS` | scaled: 250ms/artifact, clamped 10–60s | Hard time budget for the blocking prefetch phase; artifacts past the deadline are fetched on demand by the wrapper instead. |
| `STOW_CACHE_POLICY_PATH` | wired by parent | Directory of `allow/<target>/<c_metadata>` marker files. The wrapper only consults the public cache for invocations with a marker; the parent `stow check` writes the markers from the edge graph analysis. |
| `STOW_WRAPPER_PATH` | unset | Overrides the runtime wrapper binary `stow setup` points `.cargo/config.toml` at (defaults to the current executable). |
| `RUST_LOG` | unset | Standard tracing-env-filter directive (e.g., `stow_cli=debug,info`). |

## stow-admin

| Variable | Default | Purpose |
|---|---|---|
| `STOW_EDGE_URL` | _required_ | Edge URL the admin POSTs scheduler enqueue requests to. |
| `SCHEDULER_AUTH_TOKEN` | _required_ | Shared secret for `/api/v1/scheduler/tasks/submit`. |

## stow-build (CI runner)

The runner has three subcommands. `stow-build build --output-dir <dir>` is
the untrusted stage (compiles the task crate, writes task, plan and blobs into
`<dir>`); `stow-build publish --input-dir <dir> [--build-outcome <result>]` is
the trusted stage (validates `<dir>`, then pushes, signs, registers and
reports); `stow-build serve --listen <host:port>` is the dev-only local
dispatch endpoint. Both stages read the task from `STOW_BUILD_TASK_JSON`,
which the workflow fills from its `workflow_dispatch` input.

| Variable | Stage | Purpose |
|---|---|---|
| `STOW_BUILD_TASK_JSON` | build, publish | Inline JSON `BuildTaskPayload`. Required. |
| `STOW_BUILD_WORKSPACE_ROOT` | build | Pre-existing path to build in instead of a tempdir. |
| `STOW_BUILD_SOURCE_ROOT` | build | Skip downloading the crate tarball; build from a pre-existing checkout at this path. |
| `STOW_BUILD_CARGO_SUBCOMMAND` | build | One of `build` / `check` / `test`. Default `build`. |
| `STOW_BUILD_RUSTC_CAPTURE_DIR` | build (set by the runner for its rustc wrapper) | Per-rustc-invocation capture sink for output snapshots and identity sidecars. |
| `STOW_BUILD_CAPTURE_IPC` | build (set by the runner inside the heel sandbox) | IPC socket the rustc wrapper streams capture records to; the host collector, not the wrapper, owns record persistence. |
| `GHCR_USERNAME` / `GHCR_TOKEN` | publish | Credentials for `oci-client` to push bundles to GHCR. Required. |
| `STOW_EDGE_URL` | publish, serve | Edge base URL for `/api/v1/admin/artifacts/register`. Required. |
| `STOW_REGISTER_AUTH_TOKEN` | publish, serve | Shared secret for the register endpoint. Required. |
| `SCHEDULER_URL` | publish, serve | The edge `/api/v1/scheduler` URL that receives `/complete` reports. Required. |
| `SCHEDULER_AUTH_TOKEN` | publish, serve | Shared secret for the scheduler completion path. Required. |
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
| `SCHEDULER` | _required_ (Durable Object binding) | Build scheduler queue. |
| `SCHEDULER_AUTH_TOKEN` | optional | When set, scheduler endpoints require this token. |
| `REGISTER_AUTH_TOKEN` | required to enable `/api/v1/admin/artifacts/register` | Trusted-CI register credential. Without this binding, the register endpoint returns 500. |
| `GHCR_TOKEN` | _required_ | Pull token for `ghcr.io/water-rs/stow-cache`. |
| `GHCR_BASE_URL` | `https://ghcr.io/v2/water-rs/stow-cache` | Override for mock-registry runs. |
| `STOW_BATCH_FETCH_CONCURRENCY` | `32` | Concurrent OCI bundle fetches per batch request. |
| `STOW_MAX_EXPANDED_TASKS` | `4096` | Cap on the size of an expanded transitive graph. |
| `STOW_LOCAL_CI_URL` | unset | When set, the scheduler dispatches to this URL instead of GitHub `workflow_dispatch`. Used by mock fixtures. |
| `STOW_DISPATCH_MIN_AGE_MINUTES` | `5` | Minimum age (minutes) a task must wait in `pending` before being dispatched, so misses can coalesce. Mock fixtures set `0`. |
| `STOW_MAX_CONCURRENT_JOBS` | `10` | Maximum concurrently dispatched CI builds. Mock fixtures set `3` because miniflare OOMs under parallel register/complete bursts. |
| `STOW_STALE_DISPATCH_MINUTES` | `60` | Age after which a `dispatched` task with no completion is assumed lost and re-queued. Must exceed the slowest expected CI build or long builds get double-dispatched. |
| `GITHUB_TOKEN` / `GITHUB_REPO` | _required when STOW_LOCAL_CI_URL is unset_ | Token (`actions: write`) and repository the scheduler triggers `workflow_dispatch` of `build-crate.yml` on. |