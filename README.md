# stow

A public prebuilt cache for Rust. Stow builds popular crates on fully auditable GitHub Actions CI, stores artifacts in OCI registries, and serves them from Cloudflare's edge — so your `cargo check` and `cargo build` can skip compilation for dependencies that already have a matching prebuilt.

The landing page at [stow.waterui.dev](https://stow.waterui.dev) explains the
cache and lets anyone request a crate to be built ahead of the miss queue
(see [`docs/API.md`](docs/API.md) for the request API and
[`docs/site/`](docs/site) for renders of the page).

## Quickstart

1. Install the CLI: `cargo install stow-cli` (or build from source: `cargo build --release -p stow-cli && install target/release/stow ~/.cargo/bin/`).
2. Wire up your project: `cd my-project && stow setup` (writes `.cargo/config.toml`'s `[build] rustc-wrapper` and the `[env]` entries `STOW_REAL_CC`, `STOW_REAL_CXX`, `CC`, `CXX`, `CMAKE_C_COMPILER_LAUNCHER`, `CMAKE_CXX_COMPILER_LAUNCHER` so the wrapper can capture native builds too).
3. Use it: `stow check`, `stow build`, `stow test` — drop-in replacements for the equivalent `cargo` subcommands. Add `--silent-compatible-upgrades` to auto-accept semver-compatible patch upgrades that gain cached artifacts.
4. Inspect coverage with `stow predict --manifest-path Cargo.toml`. If the "index has rows for" line is high but "direct deps fully covered" is low, your project's lockfile resolves dep `c_metadata` differently from the cached standalone builds — request the crates it names at [stow.waterui.dev](https://stow.waterui.dev), which queues them ahead of the miss lane (see [`docs/USAGE.md`](docs/USAGE.md)).

For the full surface area:

- [`docs/USAGE.md`](docs/USAGE.md) — every subcommand, with examples.
- [`docs/CONFIG.md`](docs/CONFIG.md) — config file schema.
- [`docs/ENVIRONMENT.md`](docs/ENVIRONMENT.md) — every env var stow reads.
- [`docs/MOCK.md`](docs/MOCK.md) — end-to-end local mock recipe (no Cloudflare or GitHub needed).
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — production deployment.
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) — common failure modes and fixes.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — wire protocol, schema, trust boundaries.
- [`PRIVACY.md`](PRIVACY.md) — exactly which anonymous usage statistics are collected and how to opt out (`STOW_NO_ANALYTICS=1`).

## On Linux, link with mold

When stow serves a project's dependencies, their compilation disappears and what is left in an edit-rebuild round is your own crate plus the link — so the link stops being noise and starts being the thing you wait for. [mold](https://github.com/rui314/mold) is a modern parallel linker, and the two effects compound: the more stow removes, the larger the link's share of what remains.

Measured on [zed](https://github.com/zed-industries/zed), against the `rust-lld` that rustc has selected itself on `x86_64-unknown-linux-gnu` since 1.90, mold is level on a full build and about **six seconds faster on every incremental re-link**. The full build is where compilation dominates and the link vanishes into it; the incremental round is the one you pay over and over. On a small project you will see nothing either way — a binary of a few hundred objects re-links in a fraction of a second whatever links it — and on targets rustc still links with GNU ld, such as `aarch64-unknown-linux-gnu`, the gap is far wider than six seconds.

stow's own Linux CI installs mold and links through it, and the CLI says so once when a Linux build resolves without it.

Install mold (`sudo apt install mold`, or a [release tarball](https://github.com/rui314/mold/releases)) and add to `.cargo/config.toml`:

```toml
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "link-arg=-fuse-ld=mold"]
```

Selecting a linker this way does not cost you the cache. Link options are inert for an rlib — rustc never runs the linker to produce one — so every dependency in the graph still resolves; only a unit that actually links (a proc-macro, dylib, cdylib or binary) is excluded, because there the options change the image that would be served.

## What is in the cache

The cache holds compiled **library and macro crates** — rlibs, dylibs and proc-macros. It never holds a binary, and it never holds your own code: your crates compile on your machine every time, and so does anything you patched, vendored or pulled from git. What stow removes is the dependency tree underneath.

A dependency is cached at one exact identity — crate, version, feature set, target, rustc version and profile — because that is what the compiler's output depends on. The same crate at two feature sets is two different artifacts, and asking for one when only the other was built is a miss, not a near-miss. This is what `stow predict` reports on, and why a project can be mostly covered and still compile a few crates itself.

Crates enter the cache from four places: the most-downloaded binary crates on crates.io and the library trees beneath them, requests anyone can make at [stow.waterui.dev](https://stow.waterui.dev), the misses real builds report automatically, and preheats run by whoever operates the cache. A crate nobody has ever asked for is not there yet; asking is what puts it in the queue.

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
      │                       │  CF D1   │      (signed, then published)
      │                       │(artifact │              │
      │                       │ records) │              v
      │                       └──────────┘      ┌──────────────────┐
      │ signed index slices, verified locally   │  GHCR (OCI):     │
      └────────────────────────────────────────>│  signed index.*  │
        (bundles stream via the edge byte path) │  + bundle blobs  │
                                                └──────────────────┘
```

1. You run `cargo check` (or `cargo build`). Stow wraps `rustc` and intercepts every compilation unit.
2. The CLI downloads a **signed artifact index** for your `(target, rustc)` slice — a zstd-compressed, cosign-signed catalog of every cached artifact — and resolves your whole dependency graph against it **locally**, the way cargo resolves against the sparse index. Your dependency graph never leaves the machine.
3. The local resolver includes **semver-upgraded versions** when available — if you request `serde 1.4.3`, the index may show `1.4.9` has a prebuilt. Since semver guarantees compatibility, the CLI can silently accept these upgrades (opt-in flag) to maximize cache hits.
4. On cache hit, the CLI streams the bundle through the edge byte path (`GET /api/v1/artifacts/…`, a Cache-API-backed relay of the GHCR blob), checks the bytes against the digest the signed index pins, verifies the cosign signature inside, and injects the outputs into the Cargo target directory — skipping compilation entirely.
5. On cache miss, the CLI posts the uncovered graph to `/api/v1/admissions`; the edge mints proof-of-work admissions, and redeeming them submits build tasks to the scheduler. The crate will be available next time.

## Architecture

Stow is split into four main components, each with a clear trust boundary.

### CLI (`cli/`)

A `rustc` wrapper installed on the user's machine, similar to sccache. When Cargo invokes `rustc`, stow intercepts the call, checks whether a prebuilt artifact is available, and either injects the cached result or falls through to normal compilation.

The CLI resolves artifact identities against a locally cached, cryptographically verified index — the dependency graph is never sent anywhere for a lookup. The only graph that leaves the machine is the *miss* set posted to `/api/v1/admissions`, and only when the index could not cover it.

Cached artifacts are materialized into Cargo's target directory with `reflink-or-copy` by default: APFS and other clone-capable filesystems share bytes with the local stow cache, while filesystems without clone support fall back to a real copy. For target directories that should hold links back to the stow cache instead, set `STOW_CACHED_ARTIFACT_MATERIALIZATION=symlink`.

### Edge (`edge/`)

A Cloudflare Worker that serves as the public HTTP layer. It is explicitly **untrusted** — it cannot write artifact records or forge cache entries.

- **Byte path** — `GET /api/v1/artifacts/{target}/{rustc_version}/{c_metadata}` streams the published bundle blob from GHCR through the Cache API; the client resolved the key locally and checks the bytes against the digest its signed index pins.
- **Admission minting** — `POST /api/v1/admissions` re-derives a posted graph's uncovered nodes against the artifact catalog (D1) and mints stateless proof-of-work admissions for them.
- **Miss logging** — when a crate has no prebuilt, records the miss and submits a build task to the scheduler.
- **Index catalog** — the admin index endpoints serve the catalog the signed index slices are built from, the ones the CLI resolves against.

### Scheduler (`edge/src/scheduler/`)

A Cloudflare Durable Object that manages the build queue. It exposes three endpoints:

| Endpoint | Access | Description |
|---|---|---|
| `/status` | Public | View current queue state |
| `/tasks/submit` | Edge, Admin | Submit build tasks |
| `/complete` | CI only | Mark a task as completed |

Tasks are **automatically deduplicated** by identity key `(crate, version, features, target, rustc_version)`. Resubmitting an existing task does not create a duplicate — it raises the request count and recomputes the priority from the latest downloads and miss count, but `first_requested_at` is untouched, so a resubmit never lets a task jump its lane's queue. The scheduler dispatches work to CI by triggering `workflow_dispatch` of `build-crate.yml` on `main`.

### CI (`ci/`)

The trusted build runner, hosted on GitHub Actions. This is the root of trust — every workflow run is public and auditable by anyone.

1. Receives the task as a `workflow_dispatch` input from the scheduler.
2. `build` job (read-only token, no secrets): builds the crate with the specified features, target, and rustc version, and hands the outputs over as a workflow artifact. Third-party build scripts run here and nowhere else.
3. `publish` job (GHCR token, OIDC): validates the build output against the task and a dependency closure it resolves itself, then pushes the artifacts to OCI storage (GHCR) and signs them with cosign.
4. Registers the artifact records by POSTing to the edge's authenticated `/api/v1/admin/artifacts/register` endpoint (`Authorization: Bearer` carrying the run's GitHub Actions OIDC token). The edge worker owns the D1 binding and writes the row; CI never holds a D1 credential.
5. Reports completion back to the scheduler, which then dispatches the next queued task.

### Admin (`admin/`)

The operations CLI the cache is run with. Its commands are documented in [`docs/USAGE.md`](docs/USAGE.md) and [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md); nothing in this README needs it.

## Version policy

Stow always builds the **latest version within each semver-compatible line**. The scheduler will never build `1.6.8` if `1.6.9` exists. When the edge receives a request, it resolves to the newest compatible patch release.

You never have to ask for a patch release specifically: a request for `1.6.8` is served by `1.6.9` when that is what was built, because semver says it can be.

## Security: trust through transparency

Stow does **not** rely on trusting the edge or the scheduler. Both are treated as untrusted infrastructure that could be compromised without affecting artifact integrity.

- **CI is the sole producer of artifacts.** Builds run on GitHub Actions, where every workflow run is public and fully auditable.
- **CI registers artifact records through one authenticated edge endpoint.** Records are POSTed to `/api/v1/admin/artifacts/register` with the run's GitHub Actions OIDC token — a per-run identity, not a stored secret. The edge worker owns the only D1 write path; CI holds no D1 credential.
- **Artifacts are stored in OCI (GHCR).** Content-addressable storage with digest verification.
- **Artifacts are signed, and identity is signature-bound.** Clients verify that an artifact was produced by the trusted CI pipeline before writing any bytes to disk, and additionally require the bundle's identity fields (crate name, version, target, rustc version, features, dependency identities) to byte-for-byte match the OCI config that the signature covers — a tamperer cannot relabel a validly-signed bundle as a different artifact. A record that points at a digest the attacker doesn't control fails signature verification on the client and is pruned by the edge.
- **The edge cannot publish or forge artifacts.** It writes D1 records authorized by the `build-crate.yml` OIDC identity (or a repo push user), mints miss admissions, and relays bundle bytes from GHCR — but it cannot forge OCI bundles, index slices, or sigstore signatures: every bundle a client receives must hash to the digest the signed index pins and carry a valid signature, both checked locally.

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
