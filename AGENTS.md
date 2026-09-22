# AGENTS.md

This file is the single source of repository instructions. `CLAUDE.md` is a
symlink to it — edit this file, never the link.

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

## The unit of build and cache is one library or macro crate

One build task builds one crate, and the cache stores what that crate compiles to:
an rlib, a dylib, or a proc-macro. `ArtifactKind` is `Rlib | Dylib | ProcMacro` and
`RustCrateType` carries no `Bin` variant — the rule is expressed in types and stays
that way. A proc-macro is compiled for the host, not the target, so it keys
differently from the rest; it is in scope all the same.

A binary or an application project is never a build unit. Its value is that it names
crates worth caching: read its `Cargo.lock`, take the crates.io entries, and enqueue
each one as an ordinary crate task. The project is not cloned, its own code is never
compiled, and whether it builds on any of our targets is irrelevant.

Per-crate tasks deduplicate: `task_id` is the blake3 of the identity tuple, so a
dependency two projects share is built once. Building a project's tree instead
recompiles that whole shared region for every project that names it.

Anything that would make a task mean "a checkout" or "a workspace" rather than "a
crate" is the rule leaking, and it belongs in the resolution step that produces the
task list, never in the task itself.

## mold is the linker on Linux, and it is mandatory

stow links with mold on Linux, on both sides of the cache. `stow setup` installs it
when it is absent and writes the linker selection into the project's cargo
configuration; a build on Linux without mold does not start. There is no fallback to
another linker, because a fallback produces artifacts keyed for a linker the cache
does not publish — the user would get a slower build and a colder cache at once,
which is the failure stow exists to prevent.

Measured on zed: against `rust-lld`, mold is level on a full build and saves about six
seconds on every incremental re-link. The full build is where compilation dominates
and the link vanishes into it; the incremental loop is the cost a developer pays over
and over. The two features multiply — serving removes dependency compile time, so
stow raises the link's share of what is left, and mold's saving is a larger fraction
of a warm round than of a cold one. Measuring either alone hides the effect, and
measuring a small project hides it entirely.

The public cache publishes only the mold variant of units that invoke the linker —
proc-macro, dylib, cdylib. They are a small fraction of any tree, they do not
recompile in an incremental loop, and their cost is one-time where the gain is per
round.

This is why the compile key carries a grid for link-affecting options rather than
refusing to cache when it sees them. The grid applies only where the unit links: an
rlib's key is unchanged, because rustc never runs the linker to produce one and the
options are provably inert there. `-C link-arg` carries arbitrary text, so the grid
holds the normalized option set, not a linker name — a build that adds `-L` or
`-Wl,-rpath=` is a different point in that space and misses for a real reason.

Never state in code, copy or comments which linker a target uses by default. It is
target- and version-dependent: rustc has selected `rust-lld` on
`x86_64-unknown-linux-gnu` since 1.90, while `aarch64-unknown-linux-gnu` still
defaults to GNU ld. The builders pin their linker rather than inheriting the runner's,
so the recorded value is one we chose and not an observation.

## What stow is for, and how that decides things

The impression stow has to leave is that a build is fast — not competitive, not
improved. Every residual cost is the product, because the user never reads the
paragraph explaining why the cost was acceptable; they only feel the build.

So when you find a cost, the first question is what removes it, never what limits its
blast radius. A trade-off is worth presenting only when both sides are genuinely
irreducible and you can show why. These are the shapes that keep turning out not to
be constraints at all:

- **A missing field is not a constraint.** The compile key could not express which
  linker produced an artifact, so linked units were refused. The answer was to add the
  field, not to narrow what the cache accepts.
- **A tool without a flag is not a constraint.** cargo has no "build only the
  dependencies" mode, but `cargo metadata` already reports exactly which packages a
  project resolves. Reaching for `--lib` or a source-stubbing trick was working around
  a wall that was not there.
- **Salvage is not a fix.** A failed build discards the dependencies it compiled, and
  the reflex is to recover them. The better question was why a binary we never publish
  was being built at all.
- **Narrowing a feature is not a fix.** A measurement showed mold winning little, and
  the reflex was to stop recommending it. The real answer was to build the cache with
  mold so the conflict could not arise.

Do not invent a requirement to justify a decision. A name was once argued for on the
grounds that the generated package might one day need a build script or feature
forwarding; it will not, because its entire content is one dependency declaration by
construction. Designing for a need that does not exist is over-engineering even when
the design it produces looks careful.

## Measuring a performance claim

Measure what the developer pays repeatedly, on a project large enough for the effect
to exist. A clean full build is dominated by compilation and hides everything else; a
small project hides link cost entirely, because a binary of a few hundred objects
re-links in a fraction of a second whatever links it. An incremental round on a large
workspace is the number that decides.

A measurement on one small project is not evidence about large ones, and a conclusion
drawn from it that would change a default for every user is not a conclusion. Say what
was measured and on what, and do not generalize past it.

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
- Do not make a build task mean anything other than one library or macro crate; binaries are names, never units.
- Do not state which linker a target uses by default; it is target- and version-dependent.
- Do not present a residual cost as a trade-off before trying to remove it.
- Do not expand `CI_TARGET_TRIPLES` for any individual project; the matrix multiplies every crate in every wave.
- Do not treat local Wrangler runtime failures as proof that repo logic is wrong without evidence.
