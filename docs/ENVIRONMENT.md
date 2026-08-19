# Environment variable reference

Single source of truth for every env var stow reads. Each row lists the
component(s) that read the variable, the default, and the purpose.

## CLI / wrapper (`stow`, `cargo-stow`)

| Variable | Default | Purpose |
|---|---|---|
| `STOW_EDGE_URL` | _required_ | HTTPS URL of the edge worker. Falls back to `~/Library/Application Support/stow/config.toml` (macOS) or `~/.config/stow/config.toml` (Linux) `edge_url` if unset. |
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

The trusted build runner reads its task either from `GITHUB_EVENT_PATH`
(production GitHub Actions `repository_dispatch` event) or from
`STOW_BUILD_TASK_JSON` (the local-CI dispatch path).

| Variable | Default | Purpose |
|---|---|---|
| `GITHUB_EVENT_PATH` | unset | Path to the GitHub Actions event payload. Production CI sets this. |
| `STOW_BUILD_TASK_JSON` | unset | Inline JSON `BuildTaskPayload`. Used by the local-CI dispatch endpoint when spawning a child build. |
| `STOW_BUILD_ONLY` | `0` | When `1`, the CI runner only builds + scans + emits artifact files; it skips push/sign/register/notify. Used by the local-CI dispatch path so a child build doesn't double-register. |
| `STOW_BUILD_WORKSPACE_ROOT` | random temp dir | Pre-existing path the CI runner should reuse instead of creating a tempdir. |
| `STOW_BUILD_SOURCE_ROOT` | unset | Skip downloading the crate tarball; build from a pre-existing checkout at this path. |
| `STOW_BUILD_CARGO_SUBCOMMAND` | `build` | One of `build` / `check` / `test`. |
| `STOW_SCAN_OUTPUT_PATH` | _required when build_only is set, otherwise generated_ | Where to write the scanned artifact list. |
| `STOW_UPLOAD_PLAN_PATH` | as above | Where to write the planned upload manifest. |
| `STOW_OCI_DIGESTS_JSON` | unset | Pre-known OCI digests when re-running a partial pipeline. |
| `STOW_ARTIFACT_RECORDS_PATH` | as above | Where to write the final `Vec<ArtifactRecord>` JSON for register/upload phases. |
| `STOW_BUILD_RUSTC_CAPTURE_DIR` | `<workspace>/.stow-rustc-capture` | Per-rustc-invocation capture sink the trusted-build wrapper writes into. |
| `STOW_REGISTER_AUTH_TOKEN` | _required for production register_ | Shared secret the CI POSTs to the edge `/api/v1/admin/artifacts/register` endpoint. Replaces the legacy Cloudflare D1 REST credentials. |
| `GHCR_USERNAME` / `GHCR_TOKEN` | _required for production push_ | Bearer credentials for `oci-client` to push signed bundles to GHCR. |
| `STOW_LOCAL_CI_LISTEN` | unset | When set to `host:port`, stow-build runs as the local-CI dispatch endpoint (mock infra) instead of as a one-shot builder. |
| `SCHEDULER_URL` | _required when LISTEN is set_ | The edge `/api/v1/scheduler` URL that the local-CI dispatcher POSTs `/complete` reports to. |
| `SCHEDULER_AUTH_TOKEN` | _required when LISTEN is set_ | Shared secret for the scheduler completion path. |
| `STOW_MOCK_REGISTRY_ROOT` / `STOW_MOCK_PUBLIC_KEY_PATH` / `STOW_MOCK_PRIVATE_KEY_PATH` | _required when LISTEN is set_ | Mock OCI registry root and PEM key paths. |

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
| `GHCR_TOKEN` | _required_ | Pull token for `ghcr.io/stow-rs/cache`. |
| `GHCR_BASE_URL` | `https://ghcr.io/v2/stow-rs/cache` | Override for mock-registry runs. |
| `STOW_BATCH_FETCH_CONCURRENCY` | `32` | Concurrent OCI bundle fetches per batch request. |
| `STOW_MAX_EXPANDED_TASKS` | `4096` | Cap on the size of an expanded transitive graph. |
| `STOW_LOCAL_CI_URL` | unset | When set, the scheduler dispatches to this URL instead of GitHub `repository_dispatch`. Used by mock fixtures. |
| `STOW_DISPATCH_MIN_AGE_MINUTES` | `5` | Minimum age (minutes) a task must wait in `pending` before being dispatched, so misses can coalesce. Mock fixtures set `0`. |
| `STOW_MAX_CONCURRENT_JOBS` | `10` | Maximum concurrently dispatched CI builds. Mock fixtures set `3` because miniflare OOMs under parallel register/complete bursts. |
| `STOW_STALE_DISPATCH_MINUTES` | `60` | Age after which a `dispatched` task with no completion is assumed lost and re-queued. Must exceed the slowest expected CI build or long builds get double-dispatched. |
| `GITHUB_TOKEN` / `GITHUB_REPO` | _required when STOW_LOCAL_CI_URL is unset_ | GitHub credentials for `repository_dispatch`. |
