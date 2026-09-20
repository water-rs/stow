# CLAUDE.md

This repository builds a public Rust artifact cache pipeline around a trusted GitHub-based build path.

## Trust model
- Trust GitHub-hosted CI as the builder.
- Trust crates.io as the canonical upstream for crate metadata and dependency graph information.
- Trusted CI registers artifact records via the edge worker's authenticated `/api/v1/admin/artifacts/register` endpoint (the caller proves a GitHub identity — Actions OIDC for CI, a push-user token otherwise). The edge owns the only write path to D1's `artifacts` table; CI does NOT hold a D1 credential.
- Edge workers are untrusted-by-default serving infrastructure: every register write is gated by GitHub-identity auth (the `build-crate.yml` OIDC pin or a repo push user), and every CLI fetch verifies cosign signatures, so a polluted record cannot be used to inject malicious code (the CLI sees a 404, edge prunes the stale row).
- Future direction: replace bearer-credential register auth with a cosign-signed request body, so the register path itself becomes signature-rooted.

## Architecture map
- `cli/`: end-user CLI and runtime wrappers.
  - `cargo_cmd.rs`: `stow check` / `predict` orchestration.
  - `index.rs`: signed artifact-index fetch/verify/cache (`stow index refresh|status`); the resolver reads the cached slice.
  - `resolve.rs`: local coverage analysis — exact, semantic, and expanded-graph matching against index rows; the dependency graph never leaves the machine for lookups.
  - `lockfile_resolver.rs`: lockfile-driven exact resolution for `cargo fetch`/predict paths.
  - `cache_policy.rs`: controls whether a rustc invocation is allowed to use public cache.
  - `inject.rs`: writes cached outputs back into Cargo target dirs.
  - `prefetch.rs`: concurrent edge byte-path prefetch of the index's covered bundles, each digest-checked against the index row's `bundle_digest`.
- `edge/`: Cloudflare Worker + Durable Object scheduler. The edge streams bundle bytes (`GET /api/v1/artifacts/{target}/{rustc_version}/{c_metadata}`, Cache API in front of GHCR) and mints miss admissions (`POST /api/v1/admissions`); it no longer resolves graphs or answers semantic/batch lookups — the CLI resolves every key against its local signed index.
  - `api.rs`: exact byte-path GET/HEAD, `/api/v1/admissions` minting, trusted admin/scheduler routes, public completion route.
  - `dependency_resolver.rs`: miss derivation for admissions + crates.io closure expansion for the human-request lane.
  - `db.rs`: D1 schema helpers and artifact-catalog queries.
  - `scheduler/`: Durable Object queue, dispatch, and miss draining.
- `ci/`: trusted build runner (`stow-build`), two stages that never share a job or a credential.
  - `stow-build build` (untrusted job, `contents: read`, no secrets/OIDC): builds the crate, scans artifacts, writes task + plan + content-addressed blobs to an output directory (`stage.rs`).
  - `stow-build publish` (trusted job): re-hashes the blobs, validates the plan against the dispatched task and a self-resolved dependency closure (`closure.rs`, `validate.rs`), then pushes OCI artifacts, signs, POSTs `Vec<ArtifactRecord>` to the edge admin/register endpoint, and reports to the scheduler.
  - The scheduler dispatches `workflow_dispatch` of `build-crate.yml` on `main`; the trusted identity lives in `types/src/trusted_builder.rs`.
- `oci/`: shared OCI push/sign/pull machinery (`stow-oci`) — bundle publish for `stow-build`, index publish for `stow-admin`, digest pulls for the CLI.
- `mock-registry/`: local mock OCI registry for simulation and tests (`populate`, `publish-index`, `index-from-records`, `serve`; speaks GHCR's anonymous bearer exchange).
- `types/`: shared API and artifact key types (`index.rs` carries the signed `ArtifactIndex` wire format).
- `admin/`: operations CLI for preheating the cache via the scheduler and publishing index slices (`index export|publish`).

## Important repo assumptions
- water-rs Actions capacity is 60 concurrent runners (20 on macOS) — a full `CI_TARGET_TRIPLES` request wave dispatches in one window; wall clock is set by the slowest (Windows) leg.
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
- Artifact lookups are local: the CLI resolves the dependency graph against a verified `index.<target>.<rustc>` slice pulled from the OCI registry (`STOW_REGISTRY_BASE_URL` overrides it for mocks). The only graph that leaves the machine is the miss set posted to `POST /api/v1/admissions` — it mints `EnqueueAdmission`s carrying HMAC challenges, and the client redeems them at `/api/v1/enqueue` with a blake3 proof-of-work. Verified redemptions stamp `admitted_at`; the admissions handler then drains a batch of admitted, previously-failed misses into scheduler enqueue requests (best-effort, marker-restoring).
- The capture wrapper's stable-identity rewrite is unconditional; captured records carry the full 64-hex blake3 `compile_key` with `c_metadata` as its 16-hex prefix. Per-phase (check vs build) keys legitimately differ because `emit` participates.
- Scheduler dispatch is tunable via `STOW_MAX_CONCURRENT_JOBS` / `STOW_STALE_DISPATCH_MINUTES` / `STOW_DISPATCH_MIN_AGE_MINUTES` bindings; failed dispatches back off exponentially, and failed/missing dependencies never block dependents.
- `edge/` is split by target: pure cache/scheduler logic compiles and unit-tests on the host (edge is in workspace default-members), while Cloudflare-bound modules are `wasm32`-gated. crates.io access goes through the `dependency_resolver::CratesIo` trait (`crates_io::CfCratesIo` in production).
- The CLI binds bundle identity to the cosign signature by requiring `manifest.json`'s config to equal the signature-covered `oci/config.json`.
- `stow-cli predict` was sped up by removing `cargo metadata` from the CLI dependency parsing path.
- Cache policy checks were optimized away from full JSON parse per rustc invocation to marker-file existence checks.
- `POST /api/v1/requests` is the Turnstile-admitted human lane: the scheduler `queue.lane` column orders `human` ahead of `miss` (FIFO within a lane, min-age exempt, promotion only ever `miss -> human`), tasks enqueue `EnqueueSource::HumanRequest` for the crate's dependency closure across `stow_types::api::CI_TARGET_TRIPLES`, and `rustc_version` comes from the DO-cached stable channel manifest (`edge/src/rust_channel.rs`, 60-minute TTL).

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
