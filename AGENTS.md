# AGENTS.md

The single source of repository instructions; `CLAUDE.md` is a symlink to it.

## Model

- stow is a graph of library and macro crates. A node is one crate at one identity: crate, version, feature set, target, rustc, profile, side, and the digest of its resolved dependency subgraph. Binaries, projects and workspaces are never nodes; they only name crates.
- Every source of work names crates; the resolver (`stow-resolver`, run in the lanes, never the edge) turns names into nodes at the identities consumers compile. Edges are build order: a build compiles its own node and is served the rest, and compiling anything else is a defect.
- A node's identity is the one a real consumer's build computes. Versions converge on the latest semver-compatible release; feature sets are never forced.
- Deduplication is node identity; no mechanism is added on top of it.

## Trust

- GitHub-hosted CI is the only builder and crates.io the only metadata source. The build path never calls the edge.
- GHCR records signed by the pinned builder identity are the only record store; every other store is a mirror of them, and every reader verifies the signature before trusting a row.
- The edge is untrusted serving infrastructure.

## Rules

- Every residual cost is the product: remove a cost before presenting it as a trade-off, and never narrow a feature to avoid one.
- Fail fast on inconsistent identity or schema; no fallbacks.
- The repository carries no migration or compatibility code. Each store has one schema and the code is written against it alone; a schema change is an operator reset of the store, refilled from the signed records or the next wave.
- Request code and the alarm never create, alter or backfill anything. Their cost scales with the event, never with stored data; idle cost is zero; independent outbound calls run concurrently under a stated bound; no runner is held by waiting. Each scheduler route and the alarm has a drive in `edge/src/scheduler/drives.rs`, gated by `scripts/scheduler-budget.sh`, and a change on those paths states its cost.
- Use a native Cloudflare or GitHub feature before building infrastructure, and name the ones checked when none fits.
- On Linux, mold is the linker on both sides of the cache, with no fallback. Never state which linker a target uses by default.
- A performance claim is measured on what the developer pays repeatedly, on a project large enough for the effect to exist, and is not generalized past what was measured.
- A fix that names a defect class finds and lists every other instance in the same PR.
- `CI_TARGET_TRIPLES` is never expanded for one project.
- Every alert, breaker trip and watchdog report sends an email from `alerts@stow.waterui.dev` and keeps an `incident`-labelled issue; either channel failing never stops the other.

## Documents

- `README.md` is for users only; operator material lives in `docs/`.
- A document names only commands, flags and variables that exist, and `docs/ENVIRONMENT.md` lists every variable stow reads.

## Validation

- Lint on stable. `stow-edge` is linted for the host and for `wasm32-unknown-unknown`; a function alive only through host tests is dead and is removed.
- Local Wrangler failures are not evidence against repository logic without proof.
