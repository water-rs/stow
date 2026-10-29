# Stow Architecture

This document spells out the protocols, schemas, and invariants that the
high-level [README](../README.md) summarizes. It is the authoritative spec for
anyone integrating with or modifying the trust-critical paths.

## Crates

- `cli/` (`stow-cli`, the `stow` binary): the end-user CLI and rustc
  wrapper. `cargo_cmd.rs` orchestrates `stow check|build|test`;
  `index.rs` fetches, verifies and caches the signed index slices the
  resolver reads; `resolve.rs` does local coverage analysis against
  index rows — the dependency graph never leaves the machine for
  lookups; `lockfile_resolver.rs` drives lockfile-exact resolution for
  the `cargo fetch`/`predict` paths; `cache_policy.rs` decides whether a
  rustc invocation may use the public cache; `inject.rs` writes cached
  outputs back into Cargo target dirs; `prefetch.rs` prefetches covered
  bundles from the edge's byte path, digest-checked against the index
  row's `bundle_digest`; `state_db.rs` keeps the wrapper's local SQLite
  state.
- `edge/` (`stow-edge`): the Cloudflare Worker plus the scheduler
  Durable Object. `api.rs` serves the digest-addressed bundle byte path,
  the admissions/enqueue endpoints, the Turnstile-admitted request lane
  and the trusted admin routes; `dependency_resolver.rs` holds the
  edge's crates.io reads; `scheduler/` is the DO — queue, dispatch
  and request records (schema at
  `edge/src/scheduler/schema.sql`).
  The crate is split by target: pure catalog/scheduler logic compiles
  and unit-tests on the host, Cloudflare-bound modules are
  `wasm32`-gated, and crates.io access goes through the
  `dependency_resolver::CratesIo` trait (`CfCratesIo` in production).
- `ci/` (`stow-build`): the trusted build runner's two stages —
  `build` (untrusted job: compile, scan, write task + plan +
  content-addressed blobs) and `publish` (trusted job: re-hash,
  validate against the dispatched task and a self-resolved dependency
  closure, push the bundle and the signed records to GHCR).
- `oci/` (`stow-oci`): shared OCI push/sign/pull machinery — bundle
  publish for `stow-build`, index publish for `stow-admin`, digest
  pulls for the CLI.
- `resolver/` (`stow-resolver`): the native graph resolver on the
  published `cargo` crate — materializes a fetched source, runs cargo's
  own resolver per CI target with the toolchain's real rustc facts and
  emits the per-target unit set plus the `EnqueueRequest` conversion
  the lanes share.
- `admin/` (`stow-admin`): the operations CLI — index
  export/publish/sync, preheat lanes (`preheat manual` resolves
  in-process and submits a whole wave to the scheduler), `request resolve` (the
  Actions half of the request lane), queue mutations and the scheduler
  reset. Every lane resolves in-process with `stow-resolver`.
- `mock-registry/` (`stow-mock-registry`): the local mock OCI registry
  for simulation and tests.
- `types/` (`stow-types`): shared API and artifact key types —
  `index.rs` carries the signed `ArtifactIndex` wire format,
  `trusted_builder.rs` the pinned builder identity.
- `shim/` (`stow-shim`): the rustc wrapper shim and shared constants.

## Identity

Every cached artifact is uniquely identified by a five-element tuple. All wire
types in `stow_types::api` carry these as **structured newtypes** (no raw
strings), so the rules below are enforced by `serde::Deserialize` at the API
boundary rather than by ad-hoc validators in each handler.

| Component | Newtype | Defined in | Allowed shape |
|---|---|---|---|
| Crate name | `CrateName` | `types/src/identity.rs` | ASCII alnum + `-`, `_`; 1–128 chars |
| Crate version | `CrateVersion` | `types/src/identity.rs` | strict `semver::Version` |
| Features | `FeaturesJson` | `types/src/identity.rs` | strictly sorted, deduplicated; serialized as JSON-encoded string for SQL column compatibility |
| Target triple | `TargetTriple` | `types/src/identity.rs` | ASCII alnum + `-`, `_`; 1–128 chars |
| Rustc version | `WireRustcVersion` | `types/src/identity.rs` | ASCII alnum + `.`, `-`, `_`; 1–64 chars |

In addition, the cache key uses:

| Component | Newtype | Notes |
|---|---|---|
| `c_metadata` | `CMetadata` | Cargo's `-C metadata` value: 1–64 ASCII hex chars |
| `dependency_c_metadata_json` | `DependencyCMetadataJson` | Sorted by `(crate_name, c_metadata)` pair; required for `compile_key` derivation |

`compile_key = blake3("stow-compile-key-v1" || crate_name || version || target ||
rustc_version || features_json || dependency_c_metadata_json || kind || profile_json
|| crate_types_json || emit_json [|| embed_metadata] [|| "cfgs" || cfgs_json]
[|| "embed-bitcode=yes"])` — see `types/src/upload_plan.rs::compute_compile_key`.
The bracketed inputs are hashed only when they carry information, so an
invocation without them keeps the key it produced before they were modeled:

- `embed_metadata` (`yes`/`no`) only when the invocation carried
  `-Z embed-metadata`, the flag nightly cargo emits on every unit.
- `cfgs_json`, the sorted `--cfg` values other than `feature="…"` (a build
  script's `cargo:rustc-cfg` output, `--cfg` in `RUSTFLAGS`), only when
  there is at least one. A cfg selects code in the compiled crate, so an
  artifact built under CI's probe results never serves a unit whose local
  build script probed differently. Features stay a separate input because
  the semantic tuple registries index on is features only.
- `embed-bitcode=yes` only when the object files carry LLVM bitcode:
  `-C embed-bitcode` absent (rustc's default) or `yes`. Cargo passes
  `embed-bitcode=no` to every unit no LTO consumer needs bitcode from, and
  a unit whose consumer runs LTO carries `-C linker-plugin-lto`, which is
  custom codegen and never cached.
- `rustc-check-defaults` only when the profile differs from the dev profile
  (`opt-level` other than `0`, or debug assertions off). rustc turns debug
  assertions on only at `opt-level=0` and overflow checks follow them; keys
  stored while those defaults were mislabeled carry no tag and so never
  answer a request keyed after the correction.
- `extra_codegen` keeps its argv order: rustc applies repeated `-C
  target-feature` options left to right.

A semantic match (version upgrade, emit cover, feature superset) compares
the typed fields the rows carry, then proves the stand-in was compiled with
the request's own cfgs, extra codegen and link options: the key it would
carry under them (`types/src/upload_plan.rs::candidate_compile_key`) must be
the key it does carry. The candidate's build-script cfgs and link arguments
come from its captured `cargo:` output (the request's own for a candidate
of the same version and feature set), so a feature-dependent cfg never
blocks superset serving. Published nodes never carry a consumer cfg, extra
codegen or `embed-metadata`; the capture wrapper refuses to build one that
does, and the CLI does not download for a request that does.

Link-affecting options sit in a grid on the key rather than refusing the
cache: the grid applies only where the unit actually links (proc-macro,
dylib, cdylib) — an rlib's key is unchanged because rustc never runs the
linker to produce one. `-C link-arg` carries arbitrary text, so the grid
holds the normalized option set, not a linker name; a build that adds
`-L` or `-Wl,-rpath=` is a different point in that space. The cache
publishes only the mold variant of linkable units (the builders pin
`-fuse-ld=mold`; which linker a target defaults to is never observed,
stated or relied on — it is target- and rustc-version-dependent), and a
Linux build without mold does not start — a fallback would produce
artifacts keyed for a linker the cache does not publish.

## Misses

Every observed miss is logged as one data point in the
`stow_cache_misses` Analytics Engine dataset (binding
`STOW_ANALYTICS`) — anonymous traffic never spends billed writes. A point's blobs are `(event, crate_name, version,
features_json, target, rustc_version, kind, path)` with `event = "miss"`,
its doubles are `[1]`, and the crate name is the index. Every miss is a
`graph` point carrying the full request identity, written by the
admissions handler once per uncovered node (the `kind` slot is always
empty today); the digest-addressed byte path observes no crate identity
and writes nothing. A point carries artifact identity only — no IP, no
request id, no dependency graph, no lockfile hash. Semantic misses never
reach the edge: the CLI resolves them locally against the index slice.

A miss whose admission is redeemed enters the scheduler directly:
`POST /api/v1/enqueue` verifies the challenge and proof-of-work, then
forwards the tree — a failed send is the request's own error, not a row
a drain would retry
for failed sends (restoring the marker if the send fails again). Rows
queued more than 7 days ago are pruned opportunistically, as are
never-admitted rows older than 30 days (left over from when analysis
persisted every miss). Composite uniqueness key:
`(crate_name, version, features_json, target, rustc_version, host_side)` —
a host-side miss and a target-side miss at one semantic identity are two
rows.

Enqueue admissions are stateless — the edge keeps no per-request record.
An `/api/v1/admissions` response mints an `EnqueueAdmission` per uncovered
node, each carrying the canonical
`EnqueueRequest`, an HMAC-SHA256 challenge over
`task_id ‖ canonical request JSON ‖ issue_minute`
(`STOW_POW_CHALLENGE_SECRET`), and a proof-of-work difficulty of
`STOW_POW_MIN_BITS` leading zero bits — a constant of the deployment, so
an enqueue is never free and never expensive. Minting and redemption
compute it from the same setting, so a solved ticket is always redeemable
while its challenge lives.
The client solves `blake3(task_id ‖ challenge ‖ nonce)` and posts an
`EnqueueTicket` — the same request plus its nonce — to
`POST /api/v1/enqueue`, which recomputes the challenge over the carried
request (accepted during its issue minute and the minute after), checks
the proof-of-work, and forwards the request to the scheduler. An
unauthenticated miss therefore leaves no scheduler trace at all — only
the Analytics Engine point — and a forged or tampered request cannot
verify.

The miss lane is also depth-capped: once the scheduler reports
`pending >= STOW_MAX_QUEUE_PENDING` (the miss lane's own pending nodes; other lanes' backlog never counts) the handler refuses tickets with 429
and `Retry-After: 600`, and the Durable Object repeats the check inside
`enqueue` so a race of concurrent redemptions cannot overshoot by more
than one submit batch. Human-lane and workflow-trusted submits
(`POST /tasks/submit/trusted` inside the object) skip this gate.

### Human request lane

`POST /api/v1/requests` is the second public admission path, behind the
request form on `stow.waterui.dev`: a person asks for one crate to be
prebuilt into the public cache. Its admission check is a Cloudflare
Turnstile token instead of the proof-of-work — the audience here is a
human clicking a form, so a one-time invisible browser challenge is the
right cost; burning CPU minutes on a blake3 puzzle would only punish the
person the lane exists for, while the miss path's PoW stays sized for
scripted CLI redemption and is unchanged.

Accepted work lands in the scheduler's `human` lane at 30× the CLI
miss's priority. Every ready node ranks by its priority times the time
it has waited since it was first requested, with first-requested FIFO
ties, so a request typed here overtakes misses that have waited less
than 30 times as long while old preheat or miss work is never starved.
Human nodes are exempt from `STOW_DISPATCH_MIN_AGE_MINUTES` (the
coalescing hold exists to batch identical misses; a human already said
exactly what they want) and from the `STOW_MIN_DISPATCH_VALUE` floor.
Re-requesting a queued crate through this API promotes it to the human
lane and raises its priority to the human class; a node reached from
several entry points keeps the highest priority and its first-requested
time.

The crate named in the request is itself only a name source: the
expansion drops any package crates.io's version record marks
`has_lib: false` — the requested root and a bin-only package reachable
through a Normal/Build edge alike, since neither compiles to anything
`ArtifactKind` covers. Non-node units are transparent in the task
graph: a dependent's `depends_on` reaches the next crates.io lib past
the dropped package, so the request for a binary enqueues exactly what
`cargo install` would compile. The outcome reports that as
`closure_queued` rather than a task state.

Two hard caps bound what one Turnstile token can spend:
`STOW_HUMAN_MAX_CLOSURE` caps a request whose largest single-target
uncovered closure exceeds it — checked in the resolve job, where an
overspending request lands as a `failed` record naming the limit — and
`STOW_HUMAN_DAILY_TASK_BUDGET` limits human-lane tasks enqueued per UTC
day — the scheduler Durable Object keeps the counter
(`human_daily_task_budget`, one row per UTC date, charged atomically in
`enqueue`) and refuses an overspending submit with 429; the edge answers
`Retry-After` in seconds until 00:00 UTC.

Dispatch is additionally capped per GitHub Actions runner family —
`stow_types::api::runner_family` maps each `CI_TARGET_TRIPLES` member
onto the pool its `runs-on` entry in `build-crate.yml` resolves to
(Linux, macOS, or Windows). `STOW_MAX_CONCURRENT_JOBS` bounds total
in-flight runner slots — one per claimed `build-crate.yml`
run (`0` pauses dispatch
entirely — see `DEPLOYMENT.md`), and
`STOW_MAX_CONCURRENT_MACOS_JOBS` bounds macOS-family slots so a
full wave cannot occupy the whole macOS pool. Within a lane,
Windows-family rows claim first regardless of request age because the
Windows tasks are the slowest in a wave; rows whose family is saturated
stay pending, and the alarm then wakes at the earliest in-flight lease
expiry rather than re-firing immediately. Operators move both caps at
runtime — `stow-admin dispatch-cap set --jobs N [--macos M]` appends a
setting to the scheduler's log that replaces the binding values at
claim time until the next `set` (stow#1039): there is no clear, a
`--macos`-less `set` leaves that cap on its binding, no ceiling is
checked, and a lowered cap cancels nothing in flight — new claims
pause until the in-flight count drops below it.

The handler resolves the requested version (newest non-prerelease,
non-yanked release when the body omits it) and the current stable rustc,
then hands the request to the scheduler's `POST /requests` — the
request record (`requests` table) is born `accepted` and dispatched
there to `resolve-request.yml` on `main` through the same GitHub App
`workflow_dispatch` arm `dispatch_task` uses for `build-crate.yml`.
`resolve-request.yml` runs `stow-admin request resolve`: `stow-resolver`
expands the crate's dependency closure over crates.io metadata — normal
and build edges, optional-dependency feature activation, `cfg(...)`
target restrictions — for each of
`stow_types::api::CI_TARGET_TRIPLES`, prunes it against the published
`index.<target>.<rustc>` slices (the queue gate's own coverage truth),
and posts the plan to the trusted
`POST /api/v1/scheduler/requests/{id}/outcome`, which enqueues every
uncovered node as an `EnqueueSource::HumanRequest` task in the `human`
lane and flips the record `enqueued` in the same call. `rustc_version`
is the current stable channel release, parsed from
`channel-rust-stable.toml` and cached in the Worker's Cache API for 60
minutes (`edge/src/rust_channel.rs`), so the lane never wakes the
scheduler Durable Object to resolve it.

`GET /api/v1/requests/{request_id}` returns the request's
`CrateRequestStatus` — `accepted` → `resolving` → `enqueued` /
`failed`. The platform-native signal drives it: the HMAC-verified
`workflow_run` webhook at `POST /api/v1/github/workflow-run` matches the
resolve run by its `resolve-a<attempt>-<request_id>` run name and posts
`in_progress` (record → `resolving`, run id/url stamped) and `completed`
(a one-statement conditional `failed` backstop that can never overwrite
`enqueued`) to `/requests/{id}/run-update` inside the object. An
`enqueued` record re-reads its stored roots against the queue on each
fetch, so per-target `state`/`human_lane_position` keep moving until
every target is cached — task ids on a `queued` row and the request's
`task_id` link shape are gone: `request_id` is the lookup.

### Task dependencies and claim-time coverage

Edges are dependency edges: a task's `depends_on` names the node's own
direct dependencies, each at the dep's own `(crate, version,
features_json, target, rustc_version)` identity. Host-side units — the
proc-macro and build dependencies of the resolved graph — mint on
the runner family's host triple, and the edge a dependent carries into
one names that same host platform, so a `wasm32` consumer waits on a
`x86_64-unknown-linux-gnu` `serde_derive`. Both admission paths
(`build_enqueue_requests`) mint one task per uncovered node in the exact
graph — a package the build needs on both sides of the target/host
split is two nodes — and wave order emerges from the gate below rather
than from any pruning at mint time. A host-side node's build compiles
its crate as a wrapper `[build-dependencies]` unit and runs each phase
under both invocation spellings (native and explicit `--target`),
publishing both shapes, because cargo compiles the host half of a unit
graph under the build-override profile and the two spellings hand it
different flags; the gate serves a dependent's host edge only when the
side it needs has published.

A same-package unit can also exist on both sides at one feature set —
the host/target twin pair cargo's native build either merges into one
unit (sharing) or keeps as two. When cargo keeps them apart the host
unit compiles `debuginfo=2` over its own host dependencies under an
explicit `--target` spelling while the task's plain identity still
names the shared shape, so a third node names the host unit: the
host node carries a self-twin edge onto its target twin (`task_graph`
in `types/src/unit_graph.rs` adds `X_h → X_t` exactly when cargo's
`traverse_and_share` interning rule — the recursive comparison of the
two sides' lib dependency sets — keeps the pair apart), which re-mints
the host node's task id and pins the target twin in its wrapper. The
builder asserts cargo's native unit-graph verdict equals the predicate
for every such pair.

A minted task always builds at the latest semver-compatible version —
within a range the latest is unique and a strict improvement, so a
project's own version pins are dropped — unless the task's source asked
to keep them: `preserve_lockfile` (`ci/src/task.rs`) keeps the bundled
lockfile, whose pins still admit the yanked registry versions they name
and whose git entries lock git dependencies to the recorded sha. Feature
sets are never forced: `A` with `{c, d}` and `A` with `{c}` are two
legitimate artifacts with no ordering between them, so a task carries
its source's resolved feature set verbatim.

Between mint and claim a row may become redundant — an artifact covering
its exact `(crate, version, features_json, target, rustc_version)`
identity published in the window. `claim_dispatchable_tasks` asks the
scheduler's published mask — the membership `index report` feeds —
which of the
candidate rows' identities exist and retires those rows as `completed`
without a build. Only plain crates.io tasks are asked about — a
project-source task shares nothing with the catalog's keys, and a
lockfile-preserving overlay build is a different artifact.

Completion is not what releases a waiting dependent, though: completed
is not servable. The `index-publish` workflow reports each signed
slice's semantic membership to the edge after a publish lands
(`POST /api/v1/admin/index/published`, forwarded into the
scheduler's `published_slice_rows` tables), and the dependency gate in
`DEPENDENCY_NOT_BLOCKED_SQL` lets a pending row claim only when every
edge resolves to a row the latest report for that dependency's own
`(target, rustc_version)` serves. Ordering here is correctness, not a
cache-locality optimization — a dependent dispatched before its
dependency is servable compiles the dependency itself. A failed
dependency keeps its dependents waiting while it retries — each
failure report re-queues it under an exponential `not_before` backoff
until the attempt cap, where it parks `failed`. From there the read
paths report the dependents as `blocked`, naming the failed task
id, until the operator's `queue retry` (or a later successful build
plus publish) releases them back to `pending`.

## Schema lifecycle

Every store has exactly one schema, and the code is written against it
alone — nothing reads an older shape of a store.

- The scheduler Durable Object's schema is `edge/src/scheduler/schema.sql`,
  created by the operator reset route — `stow-admin scheduler reset
  --yes` (→ `operations.yml` → `POST /api/v1/admin/scheduler/reset` →
  the object's `/reset`) drops every table, index and trigger and
  re-executes the file, then appends a `StoreReset` row carrying the
  dispatcher's login as the fresh log's first row; the
  queue and recorded slices are destroyed and refill from the lanes
  that feed them. A store that was never initialized gets its schema
  from the same pass — a fresh deployment's operator runs it once.
  A stored record's shape is part of the schema: a change to one — the
  dispatch freeze's manual trigger carries its `actor` — lands with the
  reset.
- Request code and the alarm never create, alter, drop, backfill or
  check the schema — a request on an uninitialized store fails with
  SQLite's own `no such table` error.

## OCI bundle layout

Every artifact is a tag of its rustc's GHCR package — one package per
rustc version — referenced as
`ghcr.io/water-rs/stow-cache-<rustc>:{crate}.{version}-{target_short}-{rustc_short}-{feat_hash}-{c_metadata}{kind_suffix}`
(see `types/src/registry.rs`). The crate name is the tag's first
`.`-separated segment — crates.io names never contain `.`, so the split is
unambiguous (`sha-1.0.10.0-…` is crate `sha-1`, version `0.10.0`). A new
rustc's package is created by its first `build-crate.yml` push: it links
to the public `water-rs/stow` repository and inherits its visibility, so
no manual step ever opens one, and a retired rustc's package is deleted
whole. Before it exists — or after a deletion — GHCR answers an
anonymous pull of it with `403 DENIED` rather than `404`; every index
reader treats that answer as the empty index, the same result a missing
tag gives, so a fresh rustc's first builds can start it and a deleted
package reads as reset (stow#844).

Each artifact is two OCI images on that package. The signed image is the
tag above: its config is the `ArtifactBlobConfig` and it carries one layer,
the pack: a deterministic tar (fixed order, mtime 0, owner 0:0, mode 0644)
of every output file plus, when the build script produced one, the native
`OUT_DIR` archive, compressed as a single zstd stream at level 19 with
long-distance matching and a 2^27 window, on every core of the publishing
runner (`stow_shim::pack`). One stream shares redundancy across files — an
rlib embeds the metadata its rmeta carries. The config records each file's
SHA-256; the CLI unpacks the pack with the 2^27 window bound and verifies
every file against it. Decompression speed does not depend on the level,
so the cost is paid once, at publish. Index slices are compressed at the
same level, multithreaded; cosign signs this image. Next to it the
trusted publish stage pushes `<tag>.bundle`, a single-layer image whose
layer is the bundle tar a CLI consumes (`stow_types::bundle::assemble_bundle`).
The bundle needs no signature of its own: it embeds the signed manifest and
config, the signature materials, and the pack byte-for-byte, and the CLI
verifies that material after download. The build's records artifact
carries the bundle layer's digest and size (`bundle_digest`,
`bundle_size`), republished verbatim into the index row; the CLI asks the
edge for `GET /api/v1/bundles/{rustc_version}/{bundle_digest}`, which
streams the blob
from GHCR behind Workers Cache (the answer's immutable `Cache-Control`
lets the platform serve later reads without the Worker running), and the
CLI requires
the bytes to hash to the index row's `bundle_digest` — no intermediary
ever assembles, buffers or inspects it. The publish stage validated the tar
(`stow_types::bundle_schema`) before pushing it.

| Path | Content |
|---|---|
| `manifest.json` | `ArtifactBundleManifest` (oci_reference, oci_digest, embedded `ArtifactBlobConfig`, sigstore signatures) |
| `oci/manifest.json` | OCI image manifest of the signed image (registry bytes verbatim) |
| `oci/config.json` | OCI image config of the signed image (registry bytes verbatim) |
| `sigstore/payload-<n>.json` | Cosign simple-signing payloads, one per signature layer |
| `files/pack.tar.zst` | The signed image's one layer, the pack, verbatim; it holds `lib<crate>-<extra>.rlib`, `.rmeta`, `.so`/`.dylib`/`.dll` and the native archive in `ArtifactBlobConfig` order |

A record always carries its pushed bundle's digest — the publish
writes it — so every record maps to one index row.

Constants (media types, paths) are defined in `types/src/bundle.rs`.

The CLI reads only this layout. A node published before it stored one zstd
layer per file; `build-crate.yml` repacks those without rebuilding. A
dispatch with `repack_rustc` set (and `repack_concurrency`, tasks in
flight, default 4) runs the `repack` job under the same signing identity as
a build: `stow-build repack` lists the rustc's `records-*` artifacts,
verifies each task's records and each node still in the old layout under
the pinned builder identity, checks every file's SHA-256 against the signed
config, publishes the single-layer artifact and bundle through the build's
publish path, and pushes a new signed records artifact per task changed.
The config blob is carried over byte for byte, so a node's identity does
not change. The next index export folds the new records over the old rows.
A sweep only touches nodes still in the old layout, so it is safe to rerun,
and a second sweep after in-flight old-layout builds drain finishes the
cutover. Its run is titled `<rustc>-repack`; no scheduler task carries that
id, so the scheduler logs the completion as an orphan run.

## Artifact index

Every servable artifact row is additionally published as a signed,
per-slice index so a client resolves cache coverage locally instead of
querying the edge (#188). One index exists per `(target, rustc_version)`
pair: the tag `index.<target>.<rustc>` on `ghcr.io/water-rs/stow-cache-<rustc>`
(`stow_types::index::index_tag`) names a single-layer OCI artifact whose
layer is the zstd-compressed JSON `ArtifactIndex` (media type
`application/vnd.stow.index.v1+zstd`; config
`application/vnd.stow.index.config.v1+json`). The typed header
(`types/src/index.rs`) pins `format_version` — a decoder rejects a
foreign version — and a `row_count` checked against the decoded body.

`.github/workflows/index-publish.yml` is dispatch-only: scheduled and
`workflow_run` workflows run on the default branch (`dev`), whose
identity the CLI rejects, so `index-publish-cron.yml` dispatches it on
`main` after every completed `build-crate` run (a ten-minute schedule is
the backstop; GitHub delivers those ticks hours apart), and its first
step refuses any other ref. A run does one `stow-admin index export
--out-dir --rustc-version` pass scoped to one rustc — the completed
run's `<rustc>-<task_id>` title names it, and the pass pulls and
verifies the published `index`/`folded` pair per `(target, rustc)`
slice of that rustc and then only the `records-<rustc>-*` artifacts no
folded set covers, all from GHCR with no edge round-trip — and emits an
empty generation-1 slice for every `CI_TARGET_TRIPLES` member that got
no rows and has no published pair, so a `--target` consumer always
finds the tag —
a slice whose publish died between its `index` and `folded` tags is
extended with an empty folded set, so the pass refolds every record onto
its rows;
then loops the pass's `slices.json` for `stow-admin index publish`,
which pushes the `index` plus `folded` pair and signs both. Because the header's
`generated_at` makes every
export byte-unique, the run does not compare blob digests: the export
reports a `content_sha256` over everything but the timestamp, the
manifest carries it as the `dev.stow.index.content-sha256` annotation,
and an equal annotation skips the push (and the signature, when its
`.sig` tag is present; a missing one is signed in place) — an unchanged slice
never churns the tag. Pushed indexes are cosign-signed keyless under
`index-publish.yml@refs/heads/main`
(`stow_types::trusted_builder::INDEX_CERTIFICATE_IDENTITY`), the same
Fulcio chain the CLI verifies for artifact bundles.

The scheduler holds each reported slice's generation. A delta report
applies only on top of exactly that generation and publishes the next
one, else the route answers 409 and `index report` resends the slice in
full; a full report replaces the slice's set and restarts the sequence.
A full report larger than the edge's 2 MiB request body (a store-reset
reconcile, a first publish) is sent in parts: each part names its slice,
generation, index and part count and carries a share of the membership
bounded at 512 KiB, parts of one slice never share a body, and bodies
post in order. The scheduler appends one log row per part and stages the
parts of a slice in memory (and in the snapshot, so an eviction in the
middle of a report loses nothing); it applies the whole membership as
one replacement only when the last part arrives, so no reader sees a
partial set. A newer part 0 for the slice supersedes an incomplete
report, a delta is refused with a 409 while one is staged, and a part
that does not continue its staged report (or contradicts its part count)
is refused. `stow-admin` refuses any JSON body over the request limit
before sending it. A run whose report failed fails, and the next run's `index reconcile`
(which reads the generations from `GET /api/v1/admin/status`) reports
every published slice the scheduler does not hold before its own delta.

Every publish leaves superseded manifests in the package — an index
republish untags the previous manifest, a rebuilt task's older
`records-*` artifacts stay tagged, and each `sha256-<digest>[.sig]`
signature manifest accumulates under no retention of its own. GitHub's
package-versions API cannot enumerate a package at the cache's size, so
stow never deletes single versions: when a rustc is retired its whole
`stow-cache-<rustc>` package is deleted, and a served rustc's cache
rebuilds into its package from empty if the package is ever reset.
`docs/DEPLOYMENT.md` carries the procedure.

## Trust boundaries

### What protects the anonymous enqueue path

Four layers, and one of them is deliberately outside this repository:

1. **Zone-level IP rate limiting**, configured in the Cloudflare zone's
   Rate Limiting Rules. It is not in this repository and cannot be:
   Rate Limiting Rules are zone/WAF configuration, while wrangler config
   (and so `Skyzen.toml`) reaches only the Worker — routes, bindings, CPU
   `limits`. Zone level is also the right scope, since it protects more
   than this Worker. It is named here because it leaves no other trace in
   the tree, and reasoning about the enqueue path without knowing it
   exists leads to the conclusion that proof-of-work is all there is.
2. **`STOW_MAX_QUEUE_PENDING`** in the `/api/v1/enqueue` handler: once the
   scheduler queue is full, miss-lane tickets get 429 and a
   `Retry-After`. This is the precise form of back-pressure — it says the
   queue is full instead of making every client mine harder.
3. **Identity canonicalization and deduplication**: the queue's
   `UNIQUE(crate_name, version, features_json, target, rustc_version)`
   with `task_id` as primary key, `is_ci_target` on
   redemption, and the resolver dropping feature names the crate does not
   declare. A client cannot mint identities from arbitrary strings, so
   every task it can create is a legitimate one that will serve real
   users.
4. **The zone maintenance rules** (`stow-admin maintenance`).

Proof-of-work is a cost speed bump on top of these, not one of them. It
cannot be sized to stop abuse: the legitimate client and the attacker pay
the same price per request, and difficulty that rises with queue depth
charges whoever arrives next for a backlog everyone built — which is why
`STOW_POW_DEPTH_PER_BIT` was removed.


```
              GitHub Actions: build-crate.yml @ refs/heads/main  ← root of trust
   ┌──────────────────────────────┐        ┌──────────────────────────────┐
   │ build job (untrusted)        │ upload │ publish job (trusted)        │
   │ contents: read, no secrets   │──────► │ packages: write, id-token    │
   │ stow-build build             │ artifact│ stow-build publish           │
   │ runs third-party build.rs    │        │ validates, pushes bundles +  │
   └──────────────────────────────┘        │ records, cosign-signs        │
                                           └─┬────────────────────────────┘
                                             │
                                             ▼
  GitHub ──workflow_run webhook──►  edge worker (skyzen)
        ▲                              │ CfFetch
        │                              ▼
  client (cli)  ──── zenwave ──►  GHCR (OCI): bundles, records, index slices
        │
        │ inject
        ▼
   cargo target/
```

The build job never calls the edge: records live only in GHCR, and the
scheduler learns the outcome from GitHub's `workflow_run` webhook — the
edge verifies `X-Hub-Signature-256`, parses `display_title`
(`<rustc>-<task_id>`) into its rustc and task id, and forwards the
run's outcome to the scheduler's `POST /tasks/complete-run`. A
`success` conclusion counts only once the records artifact its publish
job pushed exists in GHCR; the edge checks that before it forwards. `stow-admin index export` rebuilds each index slice
from those signed records — the slices are the only catalog.

What each hop is allowed to do:

| Hop | Reads | Writes |
|---|---|---|
| stow CLI (`cli/`) | GHCR: signed `index.*` slices (anonymous pull); edge: bundle blobs streamed through `GET /api/v1/bundles/{rustc_version}/{digest}`, `/api/v1/admissions` + `/api/v1/enqueue` responses | local cache only |
| edge worker (`edge/`) | crates.io, GHCR, Analytics Engine SQL API | scheduler queue (enqueue submits only); `stow_cache_misses` Analytics Engine points (every miss) |
| scheduler DO | its SQLite store | its SQLite store; GitHub `workflow_dispatch` of `build-crate.yml` on `main` |
| `stow-build build` (untrusted job) | crates.io tarball, the task | its own output directory (task, plan, content-addressed blobs) |
| `stow-build publish` (trusted job) | the build output, crates.io (closure resolution), GHCR token, OIDC (`id-token: write` — cosign) | GHCR objects (bundles + `records-<rustc>-<task_id hash>-<run_id>-<run_attempt>` artifacts); sigstore signatures |
| `index-publish.yml` (dispatched on `main` by `index-publish-cron.yml`) | GHCR manifests and the registry's `records-*` artifacts; OIDC (`id-token: write`) | `index.*` tags and their sigstore signatures on `ghcr.io/water-rs/stow-cache-<rustc>`; the scheduler's published membership via `/api/v1/admin/index/published` when its `report` input is set |

The edge's remaining crates.io reads are the request route's version and
rustc lookups, the site pickers (`crates/search`, `crates/{name}/versions`,
`crates/{name}/{version}/features`), and the admissions coverage diff —
none of them resolves a dependency graph: every lane that posts tasks
(preheat via `stow-resolver`, the request lane via its outcome route)
submits resolver-canonical requests, which land verbatim.

The build and publish jobs never share a process or an environment. The build job's
`GITHUB_TOKEN` is `contents: read` and it has no `id-token` grant, so a
malicious `build.rs` or proc-macro can neither push to GHCR nor mint an OIDC
token that Fulcio would sign for. Everything it hands over is
attacker-influenced, so the publisher (`ci/src/stage.rs`, `ci/src/closure.rs`,
`ci/src/validate.rs`) establishes what it believes on its own:

- the task comes from the `workflow_dispatch` event file
  (`GITHUB_EVENT_PATH`'s `inputs.task`), not from the build job;
  the build output's copy must equal it;
- every blob is content-addressed and re-hashed against the digest the plan
  records for it;
- every planned artifact's `target` and `rustc_version` equal the task's;
- every planned artifact's `(crate, version)` is in the dependency closure the
  publisher reads itself from a fresh crates.io download with
  `cargo --unit-graph` (which plans compilation and never executes crate
  code): the units cargo's `check` and `build` phases compile on the task's
  platform. Dev-dependencies and other platforms' dependencies are never
  compiled by the pipeline, so a plan entry for one of them is a fabrication
  and is rejected;
- every `oci_reference` equals the reference the artifact's own identity
  fields produce, so a plan cannot push under another artifact's name.

Inside the build job, the untrusted half of the pipeline is additionally
confined. `cargo fetch` resolves and downloads the dependency closure on the
host, then each cargo phase runs inside a `heel` sandbox: the child starts
with no environment and no home directory, gets a deny-by-default filesystem
with explicit grants only (the toolchain and the rustup/cargo homes, the
registry sources read-only, the phase's target dir — executable, and
deliberately outside the sandbox working dir, which never executes — and the
capture dir for output snapshots), and every connection it attempts is
proxied and audited into `network-audit.jsonl`. A `build.rs` or proc-macro
in there starts with an empty environment — the runner's
`ACTIONS_RUNTIME_TOKEN` is not in it — cannot read the stow checkout, and
cannot rewrite another crate's registry source.

One residual remains on that boundary: heel's own rules grant `/proc`,
`/sys`, `/etc`, and `/run` read access unconditionally on Linux
(`heel/src/platform/linux/landlock_rules.rs`) and allow `sysctl-read` on
macOS (`heel/templates/sandbox.txt`), so sandboxed code can still read the
environments of other processes running under the same UID —
`/proc/<pid>/environ`, `kern.procargs2` — including the runner worker's
`ACTIONS_RUNTIME_TOKEN`. Narrowing that is a heel-side grant change, not
something stow can deny from here.

The capture records the scan trusts never cross the sandbox filesystem
either. The rustc wrapper sends one record per wrapped invocation — including
units with nothing restorable, so a forged record collides with a genuine
one — over heel's IPC channel to a host-side collector keyed on unit
identity; a second record for an identity aborts the stage rather than
being silently dropped. Each record carries the sha256 of every output,
computed as rustc exited, and the scan re-hashes the bytes it is about to
plan (the frozen snapshot when one exists) and aborts on any mismatch — so
an output rewritten by a later unit's build script cannot reach the plan.

The residual property after this hardening is that a build script can still
produce arbitrary bytes for *its own* crate — the trusted identity only ever
attested "built by the pipeline for task T", and that is what it still
attests — but it can neither interfere with other crates' compilations and
sources nor edit or forge the evidence the scan and the publisher rely on.

CI holds no Cloudflare credential. The edge's trusted routes authorize
by GitHub identity on the `Authorization: Bearer` header — an Actions
OIDC token minted inside the
repo (signature verified against GitHub's JWKS, with `iss`/`aud`/`repository`/
`exp` pinned and the `workflow_ref`/`job_workflow_ref`/`ref`/`run_attempt`/`actor`
claims read), or any credential GitHub would accept a
push from on the repo (probed via the `git-receive-pack` ref
advertisement — uniform across user tokens, fine-grained PATs, and
installation tokens). The second shape only reads. A mutating route
admits only the OIDC token of a workflow on its own list, run at
`refs/heads/main`, so an operator — untrusted — mutates only by
dispatching `.github/workflows/operations.yml`, which leaves a run under
their account; the token's `actor` is recorded on the first scheduler
log row the request appends and on a manual freeze record
([`DEPLOYMENT.md`](DEPLOYMENT.md#trusted-endpoint-authentication)).
The CLI verifies cosign signatures on every cache hit
(`cli/src/verify.rs`) before injecting bytes into Cargo's target directory,
and the digest-addressed fetch requires the bytes to hash to the index's
`bundle_digest`, so a polluted record (e.g. from a stolen credential)
produces a verification failure and a local compile, not malicious code.

What "verifies cosign signatures" means in `github-ci` mode: the signature
material must carry a Rekor bundle; the bundle's signed entry timestamp is
checked against the Rekor log key; the entry body (`hashedrekord`) must
record this exact signature, this exact certificate (compared as DER) and
the SHA-256 of this exact payload; the Fulcio chain and the certificate's
validity window are evaluated at the entry's integrated time, never at the
certificate's own `not_before`; the certificate's SAN and OIDC issuer must
match the trusted builder's workflow URL and OIDC issuer; and only then is the ECDSA
signature over the payload checked. A key leaked from a short-lived Fulcio
certificate therefore cannot sign anything after that certificate expires.

> **Records binding.** CI never calls the edge to record builds — each
> build's records land in GHCR as a cosign-signed `records-<rustc>-<task_id hash>-<run_id>-<run_attempt>`
> artifact under the pinned `build-crate.yml` identity, and every reader
> (`index export`, the task-resolution's manifest check) verifies
> that signature
> before trusting the rows. Every catalog read resolves against the
> signed `index.*` slices the records fold into — the registry is the
> only catalog, so nothing can become a second source of truth.
>
> **Completion binding.** GitHub's `workflow_run` webhook is HMAC-signed
> with `STOW_GITHUB_WEBHOOK_SECRET`, which only GitHub and the edge hold;
> the edge accepts a completion only for a `build-crate.yml` run on `main`
> whose `display_title` parses as `<rustc>-<task_id>`, and the
> scheduler resolves the task only after
> the records artifact
> its publish job pushed verifies in GHCR — a forged "success" cannot mint catalog rows.

## Local artifact cache

The wrapper doubles as a local artifact cache so a remote miss never costs
the same compile twice. When a registry crate's `rustc` invocation misses
both caches, the CLI runs `rustc` normally, then — on success — stores the
outputs as a **local** entry under the same identity a remote bundle would
carry (`v3/{target}/{c_metadata}` on disk, keyed by the same `compile_key` /
`c_metadata` from `stable_registry_artifact_identity`). The next worktree,
`cargo clean`, or branch switch hits the local entry instead of recompiling.

### Provenance

Every `artifact_cache_entries` row carries `provenance` (`remote` |
`local`); `CachedArtifactBundle` exposes it as the `ArtifactProvenance`
enum so call sites never string-compare. Unknown values fail fast on read.
Local rows store the sentinel `"local"` in the remote-only
`oci_reference`/`oci_digest` columns.

### Eligibility

`ParsedRustcArgs::is_locally_cacheable()` gates the store: the invocation
must produce a restorable artifact (`rlib`/dynamic library with
`c_metadata` and `--out-dir`), carry no custom codegen flags, and must not
be a workspace primary package (`CARGO_PRIMARY_PACKAGE` is unset — those
artifacts are cheap to rebuild and unstable across edits). The
`-Z embed-metadata` flag nightly cargo emits on every unit is not custom
codegen — it participates in the compile key instead. Dev and release
profiles are both eligible.

### Store discipline

A passthrough stores only clean builds: `rustc` exit 0 and every expected
output present. Outputs are reflink-or-copied into a temp dir inside the
process's staging directory — `<version>/staging/<name>/`, one `<name>`
per storing process beside a `<name>.lock` it holds exclusively for its
whole life — SHA-256 hashed from the staged bytes, then atomically
renamed into the entry dir under the fs2 exclusive entry lock. A process
that ends without dropping its handle — killed mid-store — leaves its
`<name>/` and lock behind; the next `prepare_local_cache` sweeps the
staging root, reclaiming every lock it can acquire (a dead owner) while
leaving held locks (live writers) alone. The store captures only the
rustc outputs: a unit is always served inside a rustc invocation cargo
issued, and cargo has already run the package's build script itself, so
nothing on this path needs the script's `OUT_DIR` products.

### Eviction

Local entries join the remote LRU: post-insert `evict_entries` runs against
`artifact_cache_max_bytes`, `last_accessed_ms` bumps on every hit, and
`size_bytes` charges the staged entry's bytes. Eviction is
provenance-agnostic. C/C++ objects under `cache_dir/cc/` share the same
budget and ordering through their `cc_cache_entries` rows — a store or a
hit on either side of the cache moves the whole LRU.

### Trust

A local entry is trusted by construction — it was produced by this
machine's own `rustc` — so `verify_cached_bundle_signature` refuses to
sign-check it (returning `Ok` for `Local` provenance) and every
trust-marker write rejects non-remote provenance, meaning a local entry
can never carry a verified marker. Local entries are never uploaded, and
a later remote download covering the same identity returns the existing
local bundle instead of displacing it.

## Cache preheating

The cache identity pins the exact stable `rustc_version`, so every stable
release invalidates the whole pool and it has to be re-heated from zero.
Four workflows keep it warm:

- `preheat-admin.yml` (manual, Actions-OIDC authenticated) seeds the
  shared base pool directly against the scheduler: `preheat
  top-binaries` for the top-N crates whose default version ships a
  binary target and no library, ranked by the last 90 days of
  `version_downloads` —
  the ranking and the binary check read once from the crates.io daily
  database dump — each `.crate` tarball resolved in-process by
  `stow-resolver` into ordinary crate tasks
  carrying `depends_on` edges, exactly the way the projects lane
  resolves a repository's codeload tarball — plus the projects lane
  itself: `preheat projects submit` resolves every repository the
  reviewed `preheat/projects.toml` lists and enqueues its crates.io
  graph.
- `preheat-cron.yml` (every two hours plus manual) is the unattended
  lane: nothing about it waits for a user's miss. It polls
  `channel-rust-stable.toml` and dispatches `preheat-admin.yml`
  (the top binaries and the projects lane) once per UTC day, and
  immediately when the stable channel moves — the two things that
  change what the pool should hold. An `actions/cache` entry keyed
  `preheat-<version>-<day>` is the already-dispatched marker, so the
  polls in between are no-ops and a
  failed dispatch simply retries on the next tick. Re-submitting the
  whole list is cheap: `enqueue` deduplicates on task identity and
  leaves a completed task completed, so a wave builds only what is
  missing — a failed build retries on its own `not_before` backoff.
- `preheat-missed.yml` (weekly, Mondays 06:00 UTC, plus manual) promotes
  observed demand: `stow-admin preheat missed` queries the
  `stow_cache_misses` Analytics Engine dataset for the top-K
  `(crate, version, features)` tuples per target by sampled miss volume
  over the trailing week — `semantic` and `graph` misses only, the kinds
  that carry a concrete crates.io version — and submits them to the
  scheduler in one batch through the same authenticated endpoint the
  other admin lanes use, with the miss count as the task's `downloads`
  priority signal.
- `demand-feed.yml` (hourly, five past the hour, plus manual) is the
  demand ledger's input lane (stow#523): one job pulls the signed
  `stow-admin` toolchain of `main`'s merge-queue head — the command
  ships with this change, so ticks fail visibly until a toolchain
  carrying it exists — and runs `stow-admin scheduler demand-feed`
  under the job's OIDC identity inside a 25-minute deadline. The pass
  resumes the Durable Object's durable cursor before choosing work: an
  unfinished staging attempt re-materializes from scratch under a fresh
  generation, a frozen `complete` hour delivers its original staged
  pages without a new query, and only then is the watermark's
  successor — or `--hour YYYY-MM-DDTHH`, the operator's recovery path,
  dispatched through `operations.yml` — materialized: one `analytics_engine/sql` `FORMAT JSON` query over the
  closed hour's `semantic`/`graph` misses weighted
  `sum(_sample_interval * double1)`, response streamed to disk, parsed
  on the blocking pool with whole-document validation (meta shape,
  declared `rows`, terminal EOF), staged as sequential
  manifest-chained pages of at most 256 entries / 512 KiB per
  serialized request, frozen, then delivered — `feed_deliver` calls
  under a bound of four, each of which applies the object's next
  unapplied page through the #522 atomic-acceptance path — until the
  watermark-guarded `delivered` transition, after which bounded
  `feed_cleanup` chunks retire the payloads. A failed job leaves the
  durable cursor for the next tick; nothing idles in the object.
- `preheat-projects.yml` (weekly, Mondays 05:30 UTC, plus manual) keeps
  the projects lane's source list honest: `stow-admin preheat projects
  generate` refreshes `preheat/projects.toml` — every listed entry is
  re-evaluated against the same admission rule (a git tree carrying a
  `Cargo.lock` beside a `Cargo.toml`, which drops libraries to the
  download-ranked lane) and stays while it passes, while GitHub's
  most-starred Rust repositories supply only the new candidates — and
  the job opens the diff as a pull request. The list is generated and
  merged by a human; the wave only ever reads the merged file.

## Usage statistics

Anonymous usage events go to two Analytics Engine datasets
(`edge/src/stats.rs`). `stow_cache_misses` (binding `STOW_ANALYTICS`)
holds the `graph` miss the admissions handler writes per uncovered
node. `stow_events` (binding `STOW_STATS`) holds two point kinds:

- `hit` — one point per bundle fetch the platform cache lets through
  to the Worker. The digest-addressed byte path knows only the bundle
  digest, so the point carries the digest plus request dimensions
  (rustc, CLI version, OS, country, CI/local) and the daily-salted
  install hash as its index. Most fetches never reach the Worker, so
  the count is an edge-observed lower bound used for ranking only —
  `stow-admin index join` resolves the digests to crate identities
  offline from the public signed index slices.
- `build` — one point per accepted `POST /api/v1/build-report`. The
  CLI accumulates builds, cache-served artifacts, locally compiled
  artifacts and `cpu_millis_saved` locally and posts the deltas at
  most once per UTC day per install — one Worker request and one
  point, with the same install hash and dimensions. The edge keeps no
  identity store, so the report carries no crate names or digests.

Every write is gated on the `x-stow-no-analytics: 1` request header,
which the CLI sends on every request when `STOW_NO_ANALYTICS=1` is set
(`edge/src/stats.rs`'s `AnalyticsConsent` extractor — every write takes
the consent as an argument, so the opt-out is honoured by construction).
The CLI sends no build report at all under the opt-out, and the edge
drops any report that arrives with the header regardless.

`GET /api/v1/stats` answers `UsageStats` by running the
`edge/src/sql/stats_*.sql` queries against the Analytics Engine SQL API
(`POST …/accounts/{CF_ACCOUNT_ID}/analytics_engine/sql`, authorized by
the `CF_ANALYTICS_TOKEN` secret); the answer's one-hour `Cache-Control`
lets Workers Cache replay it between runs. `GET /stats`
renders the same numbers as a public page. The full data contract —
fields, retention, opt-out — is documented in
[`PRIVACY.md`](../PRIVACY.md).

## Wire-protocol surface (HTTP)

All endpoints live on the edge worker. `?` paths use `Json<T>` extractors,
which means the body is parsed *after* the per-handler extractor chain — and
the bearer-credential extractor (`SchedulerCaller` for reads, `Mutator`
for mutations) is declared first on authenticated handlers, so
unauthorized POSTs short-circuit before deserialization.

| Method + path | Auth | Body | Response | Purpose |
|---|---|---|---|---|
| GET `/` | none | — | HTML | Landing page: numbers from the acceleration audit, how it works, and the crate request form (askama template in `edge/templates/`, Turnstile site key from `TURNSTILE_SITE_KEY`) |
| GET `/stats` | none | — | HTML | Public usage-statistics page — the `GET /api/v1/stats` numbers rendered in the site's style |
| GET `/api/v1/stats` | none | — | `UsageStats` | Anonymous usage statistics from the Analytics Engine SQL API, Workers-Cached for one hour |
| POST `/api/v1/build-report` | none | `BuildReport` | 204 | One install's daily usage counters — at most one report per install per UTC day, one `stow_events` `build` point per accepted report |
| GET `/api/v1/bundles/{rustc_version}/{digest}` | none | — | the `<tag>.bundle` blob, streamed | Byte fetch — the only artifact-serving route; the `{rustc_version}` segment names the artifact's GHCR package and the `sha256:<64 hex>` segment is the index row's `bundle_digest`, served from GHCR behind Workers Cache |
| GET `/api/v1/admin/dispatch-freeze` | Bearer: repo-workflow OIDC or push user | — | `DispatchFreeze` | Read the dispatch freeze: flag plus the stored record (what tripped it, whether the alert got out) |
| POST `/api/v1/admin/dispatch-freeze` | Bearer: `operations.yml` OIDC on `main` | `DispatchFreeze` | `DispatchFreeze` | The manual transition — engage the freeze, or lift it and resume dispatch of misses queued during it (`stow-admin dispatch-freeze status\|engage\|clear`) |
| GET `/api/v1/admin/dispatch-cap` | Bearer: repo-workflow OIDC or push user | — | `DispatchCaps` | The dispatch caps in force plus the operator setting behind them (stow#1039) |
| POST `/api/v1/admin/dispatch-cap` | Bearer: `operations.yml` OIDC on `main` | `DispatchCapSet` | `DispatchCaps` | The operator's `set` — replaces the cap bindings at claim time until the next `set` (`stow-admin dispatch-cap status\|set`) |
| GET `/api/v1/admin/status` | Bearer: repo-workflow OIDC or push user | — | `AdminStatus` | Operator view: lane depths, oldest pending age, in-flight rows with GitHub run ids, per-target 24 h outcomes — `stow-admin status` |
| GET `/api/v1/admin/queue?task_ids=…&status=&target=&rustc=&crate=&older_than=&limit=` | Bearer: repo-workflow OIDC or push user | — | `Vec<QueueTask>` | Selector-filtered queue rows (≤500), newest transition first — `queue list` and the mutation preview |
| POST `/api/v1/admin/queue/{retry\|cancel\|promote\|purge}` | Bearer: `operations.yml` OIDC on `main` | `QueueSelector` | `QueueMutationResult` | Queue transitions; the verb's domain predicates conjoin with the selector — `queue retry\|cancel\|promote\|purge` |
| GET `/api/v1/admin/coverage/{crate_name}?version=&target=` | Bearer: repo-workflow OIDC or push user | — | `CrateCoverage` | Per-CI-target servable identities for one crate — `coverage` |
| GET `/api/v1/admin/artifacts?rustc_version=&target=&crate=&limit=` | Bearer: repo-workflow OIDC or push user | — | `Vec<ArtifactRecord>` | Bounded catalog listing (≤1000) — the prune preview |
| GET `/api/v1/admin/artifacts/{target}/{rustc_version}/{c_metadata}` | Bearer: repo-workflow OIDC or push user | — | `ArtifactInspection` | Catalog row plus the bundle's OCI manifest from GHCR — `artifacts inspect` |
| POST `/api/v1/admin/artifacts/prune` | Bearer: repo-workflow OIDC or push user | `ArtifactPruneRequest` | `ArtifactPruneResponse` | Delete a retired toolchain's catalog rows; GHCR tags are not deleted — `artifacts prune` |
| POST `/api/v1/admissions` | none | `AdmissionRequest` | `Vec<EnqueueAdmission>` | Mint enqueue admissions for a posted miss or inexact-hit report (`source`) — the only call that ships the dependency graph off the machine |
| POST `/api/v1/enqueue` | HMAC challenge + proof-of-work | `EnqueueTicket` | `OkResponse` | Redeem a miss admission into a scheduler enqueue |
| POST `/api/v1/requests` | Cloudflare Turnstile token | `CrateRequest` | `CrateRequestStatus` | Human request: admit and dispatch a `resolve-request.yml` run that enqueues the crate's closure on every CI target in the human lane |
| GET `/api/v1/requests/{request_id}` | none | — | `CrateRequestStatus` | Live request record: `accepted` → `resolving` → `enqueued`/`failed` plus per-target states |
| GET `/requests/{request_id}` | none | — | HTML | The same `CrateRequestStatus` rendered as a page, the link the request form returns |
| POST `/api/v1/scheduler/requests/{request_id}/outcome` | Bearer: `resolve-request.yml` OIDC on `main` | `RequestOutcomeReport` | `CrateRequestStatus` | The `resolve-request.yml` job's submission — enqueues the resolved tasks and settles the request record |
| GET `/api/v1/crates/search?q=&limit=` | none | — | `CrateSearchResponse` | crates.io search, proxied for the request form's completions; query must be ≥2 chars, limit clamps to 1–25 (default 10), response cached 5 min |
| GET `/api/v1/crates/{crate_name}/versions` | none | — | `CrateVersionsResponse` | Published, non-yanked versions newest-first — the form's version picker; cached 10 min |
| GET `/api/v1/crates/{crate_name}/versions/{version}/features` | none | — | `CrateFeaturesResponse` | Every selectable feature, `default` first — the form's feature checkboxes; cached 10 min |
| POST `/api/v1/scheduler/tasks/submit` | Bearer: `operations.yml`, `preheat-admin.yml` or `preheat-missed.yml` OIDC on `main` | `Vec<SubmissionTree>` | `SchedulerSubmitResponse` | Submit one task batch |
| POST `/api/v1/scheduler/tasks/submit-ids` | Bearer: `operations.yml` or `preheat-admin.yml` OIDC on `main` | `SubmitTaskIdsRequest` | `SubmitTaskIdsResponse` | Submit stored subgraphs by task id — `preheat projects submit` |
| POST `/api/v1/admin/scheduler/reset` | Bearer: `operations.yml` OIDC on `main` | — | `SchedulerResetReport` | Drop and recreate the scheduler store — `scheduler reset` |
| POST `/api/v1/admin/scheduler/demand`, `…/demand-feed/{query\|begin\|page\|complete\|cleanup\|deliver}` | Bearer: `operations.yml` or `demand-feed.yml` OIDC on `main` | demand-feed request types | demand-feed reports | The demand ledger's input lane — `scheduler demand-feed` |
| POST `/api/v1/admin/index/published` | Bearer: `index-publish.yml` OIDC on `main` | `PublishedRunReport` | `OkResponse` | One body of a publish run's slice membership (a large full report arrives as several, in order) — `index report`, `index reconcile` |
| POST `/api/v1/github/workflow-run` | `X-Hub-Signature-256` HMAC (`STOW_GITHUB_WEBHOOK_SECRET`) | GitHub `workflow_run` webhook payload | `OkResponse` | GitHub reports a `build-crate.yml` run completed; the edge parses `display_title` (`<rustc>-<task_id>`) → task id and forwards the run's identity to the scheduler's `POST /tasks/complete-run`; the alarm's resolution completes the task only once the records artifact its publish job pushed verifies in GHCR |
| GET `/api/v1/scheduler/status` | none | — | `SchedulerStatus` | Queue introspection — lane depths for `stow-admin status --watch` (stow#853); `Cache-Control: no-store` |
| GET `/api/v1/scheduler/health` | none | — | `SchedulerHealth` | Uncached liveness for uptime monitors (stow#860): worker/scheduler verdict, dispatch-freeze state and last `workflow_run` delivery age; any unhealthy component answers 503, all under `Cache-Control: no-store` |

Authenticated POSTs resolve the `Authorization: Bearer` credential to a GitHub identity in the extractor, before the body is parsed. Rows marked `repo-workflow OIDC or push user` are reads; the other authenticated rows name the workflows whose OIDC token, run on `main`, may call them.

Every `/api/v1/` path sits behind the zone rate-limit rule documented in
[`DEPLOYMENT.md`](DEPLOYMENT.md#one-time-cloudflare-setup) — 60 requests
per 10 seconds per source IP over the API prefix, not per route. The
`/api/v1/bundles/` byte path is carved out of it: a warm build streams
its closure at the CLI's prefetch concurrency and the per-`rustc` wrapper
fetches on demand under cargo's job parallelism, so one address
legitimately sends tens of bundle requests a second, and a Workers Cache
hit there spends only the billed request itself — no Worker CPU,
subrequests or Durable Object work. The trusted
write endpoints (`scheduler/tasks/submit`,
`github/workflow-run`) are inside the limited prefix, which is fine at
their request rate: a wave submits per slice and GitHub
delivers one webhook per run.

When even that is too much — Cloudflare has no spend cap — the zone's
maintenance rules stop traffic outright. Three WAF custom rules live on
the `waterui.dev` zone's `http_request_firewall_custom` phase (created
disabled by `stow-admin maintenance ensure` in `deploy-edge.yml`,
matched by description, so a redeploy never stomps a live toggle):
`stow maintenance: anonymous` blocks every route on the edge host
except the trusted `/api/v1/admin/*` and `/api/v1/scheduler/*`
prefixes; `stow maintenance: scheduler lanes` blocks exactly the public
routes whose handlers reach the scheduler Durable Object
(`scheduler_lanes` in `types/src/api.rs`) — the partial reopening where
bundle bytes keep serving; and `stow maintenance: all` blocks the
whole hostname. `stow-admin maintenance on --scope anonymous` (run by
`operations.yml`, which holds the Cloudflare token) flips the
rule's `enabled` flag through the Rulesets API; the watchdog (#450)
trips by enabling the scope its breach costs — `lanes` for the
scheduler Durable Object's billed dimensions and the build-pipeline
signals, `anonymous` for the Worker's — and the widest when several
breach. Blocked requests are answered in the
security phase — they never invoke the Worker and never reach the
Durable Object, so the shed costs nothing and a broken edge cannot
silence the breaker. The trusted prefixes and the GitHub webhook route
stay up under `anonymous`, so record syncs and completion webhooks keep
flowing and the operator can always flip the rule back off.

The zone's WAF maintenance rules protect the worker; the **dispatch freeze** protects the
runner allowance and the Cloudflare bill. The object is event-driven —
nothing polls, nothing wakes on a timer: two trips evaluate on the events
that change their inputs. A task's completion — applied when the
task's resolution settles it — upserts one
five-minute bucket in `attempt_outcome_buckets` per target — retried
attempts keep counting — and the object sums the trailing window's
buckets (at most `window / 5min` per target whatever the traffic) and
trips when a
stream (the fleet aggregate, or any single target) reaches both the
minimum sample and the failure ratio (never either alone: a bare ratio
false-positives on tiny samples, a bare count trips constantly at high
volume). The cost trip is self-metered: `MeteringBackend`, a `DurableDbBackend`
wrapper the middleware installs in place of the request's `DurableDb`,
reads `rowsRead`/`rowsWritten` off every statement's cursor — the exact
counters Cloudflare bills on — and a per-request settle folds them into
the graph's in-memory day meter, checkpointed to the one-row `meter`
table at each wake and snapshot; the moment a UTC day's totals pass (80% of the monthly
included allowance / 30 × `STOW_COST_BUDGET_MULTIPLIER`), dispatch
freezes on the operation that crossed it. On a trip the
object writes a `dispatch_freeze` record into `settings` — a different
flag, storage key, and purpose from the WAF maintenance rules — and `dispatch_pending`
gates on it, so the queue keeps accepting misses while nothing more is
handed to runners. While frozen, the work-submitting routes
(`scheduler/tasks/submit`, `scheduler/requests/{id}/outcome`) answer 503
naming the trigger; the `github/workflow-run` webhook and the task
completion it forwards stay open so
in-flight builds still land. Recovery is manual only:
`POST /api/v1/admin/dispatch-freeze` (`stow-admin dispatch-freeze clear
--yes`, which dispatches `operations.yml`) lifts the freeze and
immediately resumes dispatch, while
`dispatch-freeze status` shows the trigger, the alert outcome, and the
transition log (engaged/cleared events with their triggers). A manual
trigger names the `actor` of the `operations.yml` run that flipped the
switch, in the record, the transition log and the alert mail.

Alerting is split by who owns the fact. The edge sends **email only** —
one transition mail per change through the `send_email` binding
(`alerts@stow.waterui.dev` → `me@lexo.cool`), naming the counts, window,
dominant failure classes (the failure's error first line), and example Actions
run URLs. The `incident`-labelled issue record is the external
watchdog's (#450): it runs in Actions with `issues: write`, reads the
freeze state and transition log off the admin route every 15 minutes,
writes and closes the issue, and posts the hourly still-frozen digest —
the edge's `stow-ci` App token carries no `issues` grant by design (the
edge is untrusted serving infrastructure). Account-wide cost and
edge-health signals (request error rate, exceeded CPU/memory, billed
usage over the current UTC month against the 80% line) are the watchdog's too — the GraphQL Analytics API is only
read from Actions, never from the edge.

Which builds failed is a third channel neither of those owns: the
failure *rate* alerts, an alert per build would be noise. Once a day
`build-failure-digest.yml` runs `stow-admin builds digest` — it lists
the `build-crate.yml` tasks that failed in the previous 24 hours,
classifies each by the step it died in (the manual driver's
verdict/infrastructure classes), and posts one comment on the single
open `incident`-labelled issue `Daily failed builds` — opened on the
first failing day, closed by a clean day. It is the one alert that
sends no mail: the issue is the whole record (AGENTS.md).

## Tunables (Cloudflare bindings)

The edge worker reads runtime knobs from `vars` bindings via
`runtime_settings::ResolverSettings::from_env`. Defaults apply when a binding
is unset or malformed.

| Binding | Default | Purpose |
|---|---|---|
| `STOW_MAX_EXPANDED_TASKS` | 4096 | Cap on the size of an expanded transitive graph |
| `SCHEDULER` (Durable Object binding) | required | Build scheduler |
| `GITHUB_REPO` | `water-rs/stow` | Repo every trusted credential must resolve inside (OIDC `repository` claim / push-permission check) |
| `STOW_OIDC_AUDIENCE` | `https://stow.waterui.dev` | `aud` the edge pins on Actions OIDC tokens; must equal the repo variable CI requests |
| `STOW_POW_CHALLENGE_SECRET` | required (secret) | HMAC key minting and verifying enqueue-admission challenges |
| `STOW_POW_MIN_BITS` | `12` | Leading-zero bits of enqueue proof-of-work, minted into every admission and required of every ticket. About 0.27 ms of expected work at a measured 66 ns/hash. Capped at 24 bits, which guards a misconfiguration rather than load |
| `STOW_MAX_QUEUE_PENDING` | `2000` | Miss-lane pending depth (other lanes' backlog not counted) at which miss-lane enqueues are refused (429 + `Retry-After: 600`); checked in the edge handler and in the scheduler object. Human-lane and trusted submits are exempt |
| `STOW_HUMAN_MAX_CLOSURE` | `150` | Largest dependency closure `POST /api/v1/requests` accepts per target; larger closures get 422 |
| `STOW_HUMAN_DAILY_TASK_BUDGET` | `2000` | Human-lane tasks accepted per UTC day, counted in the scheduler object's `human_daily_task_budget` table; overspending submits get 429 + `Retry-After` to 00:00 UTC |
| `TURNSTILE_SITE_KEY` | `0x4AAAAAAE8LjhnMsqdVhiSp` | Public site key of the request page's invisible Turnstile widget |
| `TURNSTILE_SECRET_KEY` | required (secret) | Turnstile secret `POST /api/v1/requests` verifies tokens against |
| `STOW_FREEZE_WINDOW_MINUTES` | `60` | Trailing window the dispatch-freeze trip counts terminal outcomes over; long enough to see the measured failure-wave rate decisively, short enough that a stale burst cannot haunt the next day |
| `STOW_FREEZE_MIN_OUTCOMES` | `50` | Sample floor for the trip condition: a stream (fleet aggregate or one target) must record this many terminal outcomes in the window before its failure ratio is read — below it nothing trips however bad the ratio |
| `STOW_FREEZE_FAIL_PERCENT` | `50` | Failure ratio (percent) a sufficiently-sampled stream must reach to freeze dispatch; the trip needs both the sample floor and this ratio, never either alone |
| `STOW_COST_BUDGET_MULTIPLIER` | `1.0` | Scales the scheduler object's self-metered daily SQL budget (80% of the Workers Paid monthly allowances / 30 — the stow#883 line's daily share) — the trip fires on the operation that crosses it |
| `STOW_ALERT_FROM` | `alerts@stow.waterui.dev` | Sender address of freeze-transition alert emails; must live on a domain onboarded and Enabled under Compute → Email Service → Email Sending (`E_SENDER_NOT_VERIFIED` otherwise) |
| `STOW_ALERT_TO` | `me@lexo.cool` | Recipient of the freeze + clear transition emails |
| `STOW_ALERT_EMAIL` (`send_email` binding) | declared in `Skyzen.toml` only | Email Service send binding the transition alerts go through; the mock/local manifests deliberately omit it so their alert path resolves to `Disabled` and can never reach Cloudflare's sending API |

## Local development

* `cd edge && cargo check` builds the edge worker against `wasm32-unknown-unknown`
  — the target `edge/.cargo/config.toml` sets inside that directory. From the
  workspace root `cargo check -q` covers `stow-edge` too (it is a default
  member), compiling its host-testable half and skipping the
  Cloudflare-bound modules, which are wasm32-gated.
* `STOW_TRACE_FILE=/tmp/stow-cold.json stow check ...` writes a Chrome-format
  trace covering every instrumented `stow.*` span; open in chrome://tracing or
  Perfetto.
* `stow-build serve --listen 127.0.0.1:7000` starts the dev-only local
  dispatch endpoint (`ci/src/local_server.rs`), the same one
  `scripts/mock-e2e.sh` uses; production CI never invokes it.
* `stow-mock-registry` provides an OCI v2 + cosign-compatible local registry.