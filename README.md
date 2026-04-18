# stow

A public prebuilt cache for Rust. Stow builds popular crates on fully auditable GitHub Actions CI, stores artifacts in OCI registries, and serves them from Cloudflare's edge — so your `cargo check` and `cargo build` can skip compilation for dependencies that already have a matching prebuilt.

## Why

Every Rust developer compiles the same popular crates over and over. sccache helps individuals reuse their own past compilations, but nothing shares across users. Stow fills that gap: a shared, transparent, publicly verifiable cache backed by trusted CI.

## How it works

```
  your machine              Cloudflare (untrusted)              GitHub (trusted)
┌────────────┐           ┌───────────────────┐              ┌──────────────┐
│ stow CLI   │──direct──>│  Edge Worker      │──cache miss──│  GHCR (OCI)  │
│ (rustc     │  deps     │  (graph resolve,  │──proxy GET──>│              │
│  wrapper)  │<─prebuilt─│   artifact serve) │<─OCI layers──│              │
└─────┬──────┘  list     └────────┬──────────┘              └──────────────┘
      │                      miss │  ^ status
      │ inject                    v  │                      ┌──────────────┐
      v                  ┌───────────────────┐  webhook     │  GitHub      │
  cargo target/          │  Scheduler (DO)   │─────────────>│  Actions CI  │
                         │  (priority queue, │<──/complete───│  (stow-build)│
                         │   dedup, dispatch)│              └───────┬──────┘
                         └───────────────────┘                     │
                                                            CF D1 REST API
                                                            (direct write)
                                                                   │
                                                              ┌────v─────┐
                                                              │  CF D1   │
                                                              │(artifact │
                                                              │ records) │
                                                              └──────────┘
```

1. You run `cargo check` (or `cargo build`). Stow wraps `rustc` and intercepts every compilation unit.
2. The CLI sends your **direct dependencies** (crates.io only) to the edge worker. The edge resolves the full transitive dependency graph by querying crates.io, checks its artifact database, and replies with available prebuilts.
3. The response includes **semver-upgraded versions** when available — if you request `serde 1.4.3`, stow may reply that `1.4.9` has a prebuilt. Since semver guarantees compatibility, the CLI can silently accept these upgrades (opt-in flag) to maximize cache hits.
4. On cache hit, the CLI downloads the artifact from OCI storage, verifies its signature, and injects it into the Cargo target directory — skipping compilation entirely.
5. On cache miss, the edge logs the miss and submits a build task to the scheduler. The crate will be available next time.

## Architecture

Stow is split into four main components, each with a clear trust boundary.

### CLI (`cli/`)

A `rustc` wrapper installed on the user's machine, similar to sccache. When Cargo invokes `rustc`, stow intercepts the call, checks whether a prebuilt artifact is available, and either injects the cached result or falls through to normal compilation.

The CLI only sends **direct dependencies** to the edge — never the full transitive graph. The edge handles graph resolution. The response is versioned: the edge tells the CLI exactly which version has a prebuilt, and the CLI decides whether to accept.

### Edge (`edge/`)

A Cloudflare Worker that serves as the public HTTP layer. It is explicitly **untrusted** — it cannot write artifact records or forge cache entries.

- **Dependency graph expansion** — given direct dependencies, resolves the full transitive graph by querying crates.io.
- **Artifact lookup** — checks D1 for available prebuilts and returns matches, including semver-upgraded versions.
- **Artifact serving** — proxies OCI artifact fetches through Cloudflare's CDN cache.
- **Miss logging** — when a crate has no prebuilt, records the miss and submits a build task to the scheduler.

### Scheduler (`edge/src/scheduler/`)

A Cloudflare Durable Object that manages the build queue. It exposes three endpoints:

| Endpoint | Access | Description |
|---|---|---|
| `/status` | Public | View current queue state |
| `/tasks/submit` | Edge, Admin | Submit build tasks |
| `/complete` | CI only | Mark a task as completed |

Tasks are **automatically deduplicated** by identity key `(crate, version, features, target, rustc_version)`. Resubmitting an existing task does not create a duplicate — instead, it boosts the task's priority. The scheduler dispatches work to CI via GitHub `repository_dispatch` webhooks.

### CI (`ci/`)

The trusted build runner, hosted on GitHub Actions. This is the root of trust — every workflow run is public and auditable by anyone.

1. Receives a `repository_dispatch` event from the scheduler.
2. Builds the crate with the specified features, target, and rustc version.
3. Pushes the artifact to OCI storage (GHCR).
4. Signs the artifact.
5. Registers the artifact record **directly in D1** via Cloudflare's D1 REST API, bypassing the untrusted edge entirely.
6. Reports completion back to the scheduler, which then dispatches the next queued task.

### Admin (`admin/`)

An operations CLI for administrators. Used to manually submit build requests and preheat the cache (e.g., top 100 crates).

## Version policy

Stow always builds the **latest version within each semver-compatible line**. The scheduler will never build `1.6.8` if `1.6.9` exists. When the edge receives a request, it resolves to the newest compatible patch release.

By default, stow prebuilds the **top 100 most-downloaded crates** for every stable rustc version. Beyond that, any cache miss from a real user automatically queues the crate for building.

## Security: trust through transparency

Stow does **not** rely on trusting the edge or the scheduler. Both are treated as untrusted infrastructure that could be compromised without affecting artifact integrity.

- **CI is the sole producer of artifacts.** Builds run on GitHub Actions, where every workflow run is public and fully auditable.
- **CI writes to D1 directly.** Artifact records are registered via Cloudflare's D1 REST API from within CI, never routed through the edge. The edge cannot forge records.
- **Artifacts are stored in OCI (GHCR).** Content-addressable storage with digest verification.
- **Artifacts are signed.** Clients verify that an artifact was produced by the trusted CI pipeline before writing any bytes to disk.
- **The edge is read-only.** It can serve artifacts and submit build requests, but cannot modify the artifact database.

Even if the edge or scheduler were fully compromised, they cannot inject malicious artifacts. The worst an attacker can do is deny service or waste CI resources. They cannot produce, modify, or register artifacts.

## Project structure

```
stow/
├── cli/            rustc wrapper and user-facing CLI
├── edge/           Cloudflare Worker + Durable Object scheduler
├── ci/             GitHub Actions build runner (stow-build)
├── admin/          Admin operations CLI
├── types/          Shared API types and artifact key definitions
├── watcher/        Scheduled crate/rustc update feeder
├── mock-registry/  Local mock OCI registry for testing
└── shared/         Code shared across workspace crates
```

## License

See [LICENSE](LICENSE) for details.
