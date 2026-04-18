# CLAUDE.md

This repository builds a public Rust artifact cache pipeline around a trusted GitHub-based build path.

## Trust model
- Trust GitHub-hosted CI as the builder.
- Trust crates.io as the canonical upstream for crate metadata and dependency graph information.
- CI writes trusted artifact records into D1 directly.
- Edge workers are untrusted serving infrastructure and must not be treated as the root of trust.

## Architecture map
- `cli/`: end-user CLI and runtime wrappers.
  - `cargo_cmd.rs`: `stow check` / `predict` orchestration.
  - `cache_policy.rs`: controls whether a rustc invocation is allowed to use public cache.
  - `inject.rs`: writes cached outputs back into Cargo target dirs.
  - `prefetch.rs`: exact-artifact prefetch path.
- `edge/`: Cloudflare Worker + Durable Object scheduler.
  - `api.rs`: artifact serving, graph analysis, public scheduler completion route.
  - `dependency_resolver.rs`: crates.io-based dependency graph expansion.
  - `db.rs`: D1 schema helpers, semantic lookup, dependency graph miss persistence.
  - `scheduler/`: Durable Object queue, dispatch, and miss draining.
- `ci/`: trusted build runner (`stow-build`).
  - builds crates, scans artifacts, pushes OCI artifacts, signs, and registers D1 rows.
- `watcher/`: scheduled feeder for queueing crate/rustc refresh work.
- `mock-registry/`: local mock OCI registry for simulation and tests.
- `types/`: shared API and artifact key types.

## Important repo assumptions
- Production graph expansion should continue using crates.io.
- Mock GHCR / mock local CI are valid for local simulation.
- Local Wrangler/workerd dev runtime may be unstable; if local edge validation fails in dev mode, distinguish repo bugs from local runtime bugs before changing architecture.

## Development priorities
1. Keep semantic identity correct:
   - crate name
   - version
   - features_json
   - target
   - rustc_version
2. Fast-fail on inconsistent cache identity or schema state.
3. Prefer fixing root-cause identity/schema issues instead of adding fallbacks.
4. Preserve the trusted CI -> D1 registration path.

## Current implementation notes
- Scheduler queue identity must include `rustc_version` as well as `(crate, version, features_json, target)`.
- Dependency graph misses are persisted in `edge` and can be drained into scheduler enqueue requests.
- `stow-cli predict` was sped up by removing `cargo metadata` from the CLI dependency parsing path.
- Cache policy checks were optimized away from full JSON parse per rustc invocation to marker-file existence checks.

## Validation guidance
- First preference: `cargo check -q` for repo-wide type safety.
- For CLI latency work, benchmark `stow-cli predict --manifest-path /tmp/tokei/Cargo.toml` on stable toolchain.
- For local simulation:
  - mock GHCR: `stow-mock-registry`
  - mock edge: `edge/Skyzen.mock.toml`
  - note that local Wrangler dev runtime can fail independently of repo logic.
- When debugging edge graph issues, verify whether failure is in:
  - crates.io lookup
  - D1 schema/query path
  - scheduler forward path
  - local Wrangler/runtime

## What to avoid
- Do not replace crates.io as the production dependency graph source.
- Do not weaken the GitHub-trusted CI model.
- Do not add fallbacks that hide cache identity bugs.
- Do not treat local Wrangler runtime failures as proof that repo logic is wrong without evidence.
