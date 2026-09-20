# stow

A public prebuilt cache for Rust. Stow builds popular crates on fully auditable GitHub Actions CI, stores artifacts in OCI registries, and serves them from Cloudflare's edge — so your `cargo check` and `cargo build` can skip compilation for dependencies that already have a matching prebuilt.

The landing page at [stow.waterui.dev](https://stow.waterui.dev) explains the
cache and lets anyone request a crate to be built ahead of the miss queue
(see [`docs/API.md`](docs/API.md) for the request API and
[`docs/site/`](docs/site) for renders of the page).

## Quickstart

1. Install the CLI: `cargo install stow-cli` (or build from source: `cargo build --release -p stow-cli && install target/release/stow ~/.cargo/bin/`).
2. Wire up your project: `cd my-project && stow setup` (writes `.cargo/config.toml`'s `rustc-wrapper` and `CMAKE_C/CXX_COMPILER_LAUNCHER` env entries).
3. Use it: `stow check`, `stow build`, `stow test` — drop-in replacements for the equivalent `cargo` subcommands. Add `--silent-compatible-upgrades` to auto-accept semver-compatible patch upgrades that gain cached artifacts.
4. Inspect coverage with `stow predict --manifest-path Cargo.toml`. If the "index has rows for" line is high but "direct deps fully covered" is low, your project's lockfile resolves dep `c_metadata` differently from the cached standalone builds — populate the cache with `stow-admin preheat-binary-overlay` (see [`docs/USAGE.md`](docs/USAGE.md)).

For the full surface area:

- [`docs/USAGE.md`](docs/USAGE.md) — every subcommand, with examples.
- [`docs/CONFIG.md`](docs/CONFIG.md) — config file schema.
- [`docs/ENVIRONMENT.md`](docs/ENVIRONMENT.md) — every env var stow reads.
- [`docs/MOCK.md`](docs/MOCK.md) — end-to-end local mock recipe (no Cloudflare or GitHub needed).
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — production deployment.
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) — common failure modes and fixes.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — wire protocol, schema, trust boundaries.
- [`PRIVACY.md`](PRIVACY.md) — exactly which anonymous usage statistics are collected and how to opt out (`STOW_NO_ANALYTICS=1`).

## Why

Every Rust developer compiles the same popular crates over and over. Stow replaces per-machine compilation caches such as sccache with one shared, transparent, publicly verifiable cache backed by trusted CI: the same signed artifact serves every machine, and the CLI talks to the production edge at `https://stow.waterui.dev` out of the box.

## How it works

```
  your machine              Cloudflare (untrusted)              GitHub (trusted)
┌────────────┐           ┌───────────────────┐              ┌──────────────────┐
│ stow CLI   │─admissions>│  Edge Worker      │              │ GitHub Actions   │
│ (rustc     │  on miss  │  (mint PoW        │              │ CI (stow-build): │
│  wrapper)  │<──PoW─────│   admissions,     │<──records────│ builds, signs,   │
└─────┬──────┘           │   D1 owner)       │   Bearer:    │ pushes, registers│
      │                  └────────┬──────────┘  github-oidc └──┬─────────▲─────┘
      │ inject               miss │  ^ status            push+sign     │ dispatch
      v                           v  │                        │  (workflow_dispatch)
  cargo target/          ┌───────────────────┐                │
      ▲                  │  Scheduler (DO)   │<───────────────┘ /complete
      │                  │  (priority queue, │
      │                  │   dedup, dispatch)│
      │                  └────────┬──────────┘
      │                           │ writes
      │                           v
      │                       ┌──────────┐      D1 rows feed index export
      │                       │  CF D1   │      (stow-admin index publish)
      │                       │(artifact │              │
      │                       │ records) │              v
      │                       └──────────┘      ┌──────────────────┐
      │ index + bundle blobs by digest          │  GHCR (OCI):     │
      └────────────────────────────────────────>│  signed index.*  │
           pull + verify locally                │  + bundle blobs  │
                                                └──────────────────┘
```

1. You run `cargo check` (or `cargo build`). Stow wraps `rustc` and intercepts every compilation unit.
2. The CLI downloads a **signed artifact index** for your `(target, rustc)` slice — a zstd-compressed, cosign-signed catalog of every cached artifact — and resolves your whole dependency graph against it **locally**, the way cargo resolves against the sparse index. Your dependency graph never leaves the machine.
3. The local resolver includes **semver-upgraded versions** when available — if you request `serde 1.4.3`, the index may show `1.4.9` has a prebuilt. Since semver guarantees compatibility, the CLI can silently accept these upgrades (opt-in flag) to maximize cache hits.
4. On cache hit, the CLI downloads the artifact straight from OCI storage (GHCR) by content digest, verifies its signature, and injects it into the Cargo target directory — skipping compilation entirely.
5. On cache miss, the CLI posts the uncovered graph to `/api/v1/admissions`; the edge mints proof-of-work admissions, and redeeming them submits build tasks to the scheduler. The crate will be available next time.

## Architecture

Stow is split into four main components, each with a clear trust boundary.

### CLI (`cli/`)

A `rustc` wrapper installed on the user's machine, similar to sccache. When Cargo invokes `rustc`, stow intercepts the call, checks whether a prebuilt artifact is available, and either injects the cached result or falls through to normal compilation.

The CLI resolves artifact identities against a locally cached, cryptographically verified index — the dependency graph is never sent anywhere for a lookup. The only graph that leaves the machine is the *miss* set posted to `/api/v1/admissions`, and only when the index could not cover it.

Cached artifacts are materialized into Cargo's target directory with `reflink-or-copy` by default: APFS and other clone-capable filesystems share bytes with the local stow cache, while filesystems without clone support fall back to a real copy. For target directories that should hold links back to the stow cache instead, set `STOW_CACHED_ARTIFACT_MATERIALIZATION=symlink`.

### Edge (`edge/`)

A Cloudflare Worker that serves as the public HTTP layer. It is explicitly **untrusted** — it cannot write artifact records or forge cache entries.

- **Admission minting** — `POST /api/v1/admissions` re-derives a posted graph's uncovered nodes against the artifact catalog (D1) and mints stateless proof-of-work admissions for them.
- **Miss logging** — when a crate has no prebuilt, records the miss and submits a build task to the scheduler.
- **Index catalog** — the admin index endpoints feed `stow-admin index export`, which publishes the signed slices the CLI resolves against.

### Scheduler (`edge/src/scheduler/`)

A Cloudflare Durable Object that manages the build queue. It exposes three endpoints:

| Endpoint | Access | Description |
|---|---|---|
| `/status` | Public | View current queue state |
| `/tasks/submit` | Edge, Admin | Submit build tasks |
| `/complete` | CI only | Mark a task as completed |

Tasks are **automatically deduplicated** by identity key `(crate, version, features, target, rustc_version)`. Resubmitting an existing task does not create a duplicate — instead, it boosts the task's priority. The scheduler dispatches work to CI by triggering `workflow_dispatch` of `build-crate.yml` on `main`.

### CI (`ci/`)

The trusted build runner, hosted on GitHub Actions. This is the root of trust — every workflow run is public and auditable by anyone.

1. Receives the task as a `workflow_dispatch` input from the scheduler.
2. `build` job (read-only token, no secrets): builds the crate with the specified features, target, and rustc version, and hands the outputs over as a workflow artifact. Third-party build scripts run here and nowhere else.
3. `publish` job (GHCR token, OIDC): validates the build output against the task and a dependency closure it resolves itself, then pushes the artifacts to OCI storage (GHCR) and signs them with cosign.
4. Registers the artifact records by POSTing to the edge's authenticated `/api/v1/admin/artifacts/register` endpoint (`Authorization: Bearer` carrying the run's GitHub Actions OIDC token). The edge worker owns the D1 binding and writes the row; CI never holds a D1 credential.
5. Reports completion back to the scheduler, which then dispatches the next queued task.

### Admin (`admin/`)

An operations CLI for administrators. Used to submit build requests and preheat the cache (for example, the top 100 crates) through the authenticated scheduler API.

## Version policy

Stow always builds the **latest version within each semver-compatible line**. The scheduler will never build `1.6.8` if `1.6.9` exists. When the edge receives a request, it resolves to the newest compatible patch release.

Administrators can preheat the **top 100 most-downloaded crates** for a target and stable rustc version with `stow-admin preheat-t100`. Beyond that, any cache miss from a real user automatically queues the crate for building.

## Security: trust through transparency

Stow does **not** rely on trusting the edge or the scheduler. Both are treated as untrusted infrastructure that could be compromised without affecting artifact integrity.

- **CI is the sole producer of artifacts.** Builds run on GitHub Actions, where every workflow run is public and fully auditable.
- **CI registers artifact records through one authenticated edge endpoint.** Records are POSTed to `/api/v1/admin/artifacts/register` with the run's GitHub Actions OIDC token — a per-run identity, not a stored secret. The edge worker owns the only D1 write path; CI holds no D1 credential.
- **Artifacts are stored in OCI (GHCR).** Content-addressable storage with digest verification.
- **Artifacts are signed, and identity is signature-bound.** Clients verify that an artifact was produced by the trusted CI pipeline before writing any bytes to disk, and additionally require the bundle's identity fields (crate name, version, target, rustc version, features, dependency identities) to byte-for-byte match the OCI config that the signature covers — a tamperer cannot relabel a validly-signed bundle as a different artifact. A record that points at a digest the attacker doesn't control fails signature verification on the client and is pruned by the edge.
- **The edge cannot publish or serve artifacts.** It writes D1 records authorized by the `build-crate.yml` OIDC identity (or a repo push user) and mints miss admissions, but it cannot forge OCI bundles, index slices, or sigstore signatures — clients pull every byte from GHCR and verify locally.

Even if the edge or scheduler were fully compromised, an attacker cannot inject malicious artifacts. The worst they can do is pollute D1 with rows that point at digests they do not own — and those rows are detected and pruned the first time a client tries to fetch them. A future iteration will replace bearer-credential register auth with cosign-signed register requests, removing even that surface.

## Project structure

```
stow/
├── cli/            rustc wrapper and user-facing CLI
├── edge/           Cloudflare Worker + Durable Object scheduler
├── ci/             GitHub Actions build runner (stow-build)
├── admin/          Admin operations CLI
├── types/          Shared API types and artifact key definitions
├── shim/           Rustc wrapper shim shared by cli and ci
└── mock-registry/  Local mock OCI registry for testing
```

## License

stow is released under the [MIT License](LICENSE).
