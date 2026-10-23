# AGENTS.md

The single source of repository instructions; `CLAUDE.md` is a symlink to it.

## Model

- stow is a graph of library and macro crates. A node is one crate at one identity: crate, version, feature set, target, rustc, profile, side, and the digest of its resolved dependency subgraph. Binaries, projects and workspaces are never nodes; they only name crates.
- Every source of work names crates; the resolver (`stow-resolver`, run in the lanes, never the edge) turns names into nodes at the identities consumers compile. Edges are build order: a build compiles its own node and is served the rest, and compiling anything else is a defect.
- A node's identity is the one a real consumer's build computes. Versions converge on the latest semver-compatible release.
- Feature sets are never unioned. A set contained in another set of the same crate, version, target and side is served by the smallest containing set, ties broken by the sorted list; CI and the CLI apply the same rule, and the CLI moves to another set only once the whole chain its build needs under that choice is published.
- One task is one `build-crate.yml` run; dispatch is never batched.
- Deduplication is node identity; no mechanism is added on top of it.

## Architecture

- The edge is the public entry point and keeps no database. It streams bundles from GHCR with an immutable `Cache-Control`, so the Workers cache serves every repeat; caches crates.io answers in the Cache API; and forwards admissions, human requests and GitHub `workflow_run` deliveries to the scheduler.
- The CLI resolves every key against the signed index it pulls from GHCR. Its dependency graph leaves the machine only as the misses and inexact hits it reports.
- `build-crate.yml` builds one node in an untrusted job with no credentials and publishes it from a trusted job that re-validates its dependency closure. A task carries its node and its dependency subtree, which pins what it is built against.
- `index-publish.yml` folds the signed records into signed per-target, per-rustc index slices in GHCR and reports each slice to the scheduler.
- The CI interface reports how many `build-crate.yml` runs are queued and running per runner family, and submits one task as one run. It is FIFO and never reorders. Only operations tooling and the scheduler use it.
- The scheduler is one instance holding the dependency graph in memory. It persists only an append-only log and snapshots, appends an event before acknowledging it, and merges each submitted dependency tree by task id. It learns run state from `workflow_run` `in_progress` and `completed` deliveries and uses the CI interface's status only to reconcile.
- Priority lives only in the scheduler: a node's rank is its priority times the time it has waited. Its entry points are:
  - operations, at a priority the caller sets;
  - the stow CLI, behind proof of work, at a very low default priority: on a cache miss, and on a hit served by a superset instead of the exact feature set, which queues the exact chain;
  - stow.waterui.dev, at 30× the CLI's priority;
  - preheat, which submits one dependency tree per source.

## Trust

- GitHub-hosted CI is the only builder and crates.io the only metadata source. The build path never calls the edge.
- GHCR records signed by the pinned builder identity are the only record store; every other store is a mirror of them, and every reader verifies the signature before trusting a row.
- The edge is untrusted serving infrastructure.

## Rules

- Every residual cost is the product: remove a cost before presenting it as a trade-off, and never narrow a feature to avoid one.
- Fail fast on inconsistent identity or schema; no fallbacks.
- The repository carries no migration or compatibility code. Each store has one schema and the code is written against it alone; a schema change is an operator reset of the store, refilled from the signed records or the next wave.
- Request code and the alarm never create, alter or backfill anything. Their cost scales with the event, never with stored data; idle cost is zero; independent outbound calls run concurrently under a stated bound; no runner is held by waiting. Each scheduler route and the alarm has a drive in `edge/src/scheduler/drives.rs`, gated by `scripts/traffic-cost.sh`, and a change on those paths states its cost.
- Use a native Cloudflare or GitHub feature before building infrastructure, and name the ones checked when none fits.
- On Linux, mold is the linker on both sides of the cache, with no fallback. Never state which linker a target uses by default.
- A performance claim is measured on what the developer pays repeatedly, on a project large enough for the effect to exist, and is not generalized past what was measured.
- A fix that names a defect class finds and lists every other instance in the same PR.
- `CI_TARGET_TRIPLES` is never expanded for one project.
- Every alert, breaker trip and watchdog report sends an email from `alerts@stow.waterui.dev` and keeps an `incident`-labelled issue; either channel failing never stops the other. Exception: the daily failed-build digest keeps only its `Daily failed builds` issue — no mail.

## Documents

- `README.md` is for users only; operator material lives in `docs/`.
- A document names only commands, flags and variables that exist, and `docs/ENVIRONMENT.md` lists every variable stow reads.

## Validation

- Lint on stable. `stow-edge` is linted for the host and for `wasm32-unknown-unknown`; a function alive only through host tests is dead and is removed.
- Local Wrangler failures are not evidence against repository logic without proof.
