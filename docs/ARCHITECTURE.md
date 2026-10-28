# Architecture

How stow is built and why. Read it top to bottom: each section assumes the
ones before it. Operator procedures live in [DEPLOYMENT.md](DEPLOYMENT.md)
and [ADMIN.md](ADMIN.md), the CLI reference in [USAGE.md](USAGE.md), every
variable in [ENVIRONMENT.md](ENVIRONMENT.md).

## What stow is

stow serves compiled Rust dependencies. A developer runs `stow build`
(or `check`, `test`); cargo runs as usual with stow's rustc wrapper in
front of every compile. For each dependency unit the wrapper either serves
a finished artifact — from the machine's own cache or from the public
cache — or lets rustc compile it and keeps the result.

The public cache is built on GitHub-hosted runners, one crate per run,
signed by the workflow that built it and stored in GHCR. A Cloudflare
Worker (the edge) streams the bytes and holds the build scheduler. Nothing
a user downloads is trusted because of where it came from: the CLI checks
every artifact against a signature chain that ends at one workflow file on
one branch of `water-rs/stow`.

## Crates

| Directory | Crate | Role |
|---|---|---|
| `cli/` | `stow-cli` | The `stow` binary: cargo driver, rustc wrapper, local cache, index resolution, miss reporting. |
| `shim/` | `stow-shim` | The small wrapper executable cargo invokes, and constants the wrapper and builder share. |
| `edge/` | `stow-edge` | The Cloudflare Worker and the scheduler Durable Object. Host-testable logic compiles on every target; Cloudflare-bound modules are `wasm32`-only. |
| `ci/` | `stow-build` | The builder: `stow-build build` (untrusted job) and `stow-build publish` (trusted job). |
| `resolver/` | `stow-resolver` | Graph resolution on the published `cargo` crate. Runs in `stow-admin` and on Actions runners, never in the edge. |
| `admin/` | `stow-admin` | Operations CLI: preheat lanes, index export and publish, queue control, watchdog, digest, maintenance rules. |
| `oci/` | `stow-oci` | OCI push, pull, sign and verify shared by builder, admin and CLI. |
| `types/` | `stow-types` | Wire types, identities, the index format, the CI interface, the pinned builder identity. |
| `mock-registry/` | `stow-mock-registry` | Local OCI registry with mock signing for the mock stack ([MOCK.md](MOCK.md)). |

## The model

### Nodes are crates, never binaries

The graph stow builds is a graph of library and proc-macro crates. A node
is one crate at one identity:

- crate name and version;
- the feature set;
- the target triple;
- the rustc version;
- the side: target, or host for proc-macros and everything compiled for a
  build script or proc-macro;
- the digest of its resolved dependency subgraph.

The task id spells this out:
`<crate>-<version>-<blake3(features)>-<target>-<rustc>-d<dependency digest>[-host]`
(`types/src/task_graph.rs`). Profile, crate types, emit, cfgs and linker
options do not split nodes; they split artifacts inside one node's build
and live in the compile key (below).

Binaries, projects and workspaces are never nodes. A binary is linked from
its dependencies at the consumer, so caching it would cache one consumer's
link; a project or workspace is a set of names, not a compile unit.
`ArtifactKind` has no binary variant, and the builder's workspace is a
generated wrapper package with one dependency line on the task crate, so
the crate compiles in dependency position with the `-C metadata` a real
consumer derives. Every source of work — a user's miss, a website request,
a preheat list of binaries or GitHub projects — contributes crate names and
feature sets and nothing else. A bin-only package reached during
resolution is transparent: a dependent's edge passes through it to the
next library.

The dependency digest is a Merkle hash over the node's dependency edges,
as cargo's own metadata hash is. Two consumers that unify a shared
dependency differently need two different artifacts of the same crate,
and without the digest they would collide on one task id; the cache would
build one and every consumer of the other context would compile it
locally forever. With it, the same crate over the same subgraph is still
one node, so deduplication is unchanged.

### Edges are build order

An edge from A to B means A's build is served B. A node's build compiles
that node and nothing else; every dependency it needs comes out of the
cache. The builder enforces this: any unit it compiles other than the task
crate's own lib or proc-macro and its build script fails the build with
the identity it compiled and the one it expected to be served. A build
that compiled someone else's node exposed a defect upstream — a dependency
dispatched too early, or an identity derived differently from cargo — and
publishing what it compiled would hide that defect.

So the scheduler releases a dependent only when every dependency is
*servable*: present in the most recently published signed index slice of
the dependency's own target and rustc. Completed is not servable — the
index republishes after a build lands — and a dependency that failed keeps
its dependents waiting; dispatching them would make each compile the
failed crate itself.

Host units sit on their runner family's host triple. For a consumer
building target `T`, a proc-macro or build-dependency node is minted at
`host(T)` — `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin` or
`x86_64-pc-windows-msvc` — with the feature set cargo resolves for the
host side. A package needed on both sides is two nodes. A `wasm32`
consumer's `serde_derive` edge points at the Linux host node.

Cargo keys some units differently under the native spelling and under an
explicit `--target <host triple>`, because a proc-macro anywhere below a
unit changes its key between spellings. A node whose units key apart
publishes both shapes, and the dependency gate serves a dependent's edge
on a shape only once that shape is published. Where cargo keeps a host
unit and its same-feature target twin as two units, the host node carries
an edge onto its target twin; the builder asserts cargo's own unit graph
agrees with that rule.

### Identity is what a real consumer computes

A node's identity is the one a real consumer's build computes; anything
else builds artifacts nobody can hit. Two rules follow.

**Versions converge** on the latest semver-compatible release. Within a
semver range the latest release is unique and a strict improvement, so a
project's own version pins are dropped: every resolver lane deletes the
bundled `Cargo.lock` and lets cargo select. A pin a user's lockfile holds
below the latest is a miss for that user until they update, and the CLI
reports the better-covered compatible version it saw. `preserve_lockfile`
on a hand-submitted task keeps the bundled lockfile instead; no lane sets
it.

**Feature sets are never unioned.** A union nobody compiled may not
compile, and two feature sets of one crate are two legitimate artifacts
with no order between them. What is allowed is containment: a set
contained in another set of the same crate, version, target and side is
served by the smallest containing set, ties broken by the sorted feature
list (`types/src/feature_sets.rs`). A set no other set contains is built as
itself. Both sides apply the same rule so their keys match:

- Preheat resolution substitutes every contained set — in task identities
  and in every subtree node — before it submits. On the first production
  wave this cut 29% of the nodes.
- The CLI picks the same set from its index slice and compiles under it.
  It moves a node onto a containing set only once the whole chain its
  build needs under that choice is published, so switching never turns a
  hit into a miss.

A hit served by a superset rather than the exact set is an *inexact hit*.
The CLI reports it, and the scheduler queues the exact chain — the exact
node and every node above it whose subgraph changes with it — at the
lowest priority, so the cache drifts toward what users actually compile.

### Deduplication

Two sources naming the same node name the same task id, and the scheduler
merges submissions by task id. Nothing else deduplicates: no lock, no
in-flight table, no second key. `build-crate.yml` takes a concurrency group
keyed by the task id, and a run whose signed records already exist exits
without building, so even two submitters bypassing the scheduler build a
node once.

## Compile key and artifact identity

Inside one node's build, every rustc invocation produces artifacts keyed
by a stable compile key (`types/src/upload_plan.rs::compute_compile_key`):

```
blake3("stow-compile-key-v1" || crate_name || version || target
       || rustc_version || features_json || dependency_c_metadata_json
       || kind || profile_json || crate_types_json || emit_json
       [|| embed_metadata] [|| "cfgs" || cfgs_json] [|| "embed-bitcode=yes"])
```

The bracketed inputs are hashed only when they carry information:

- `embed_metadata` when the invocation carried `-Z embed-metadata`, which
  nightly cargo emits on every unit.
- `cfgs_json`, the sorted `--cfg` values other than `feature="…"` (build
  script `cargo:rustc-cfg` output, `--cfg` in `RUSTFLAGS`). A cfg selects
  code, so an artifact built under CI's probe results never serves a unit
  whose local build script probed differently.
- `embed-bitcode=yes` when the objects carry LLVM bitcode. A unit whose
  consumer runs LTO carries `-C linker-plugin-lto`, which is custom codegen
  and never cached.

The 16-hex `c_metadata` stow derives from the compile key replaces cargo's
path-dependent one, so the same unit keys the same in every checkout.

Link-affecting options are part of the key only for units that link
(proc-macro, dylib, cdylib); rustc never runs the linker for an rlib. The
key holds the normalized option set, not a linker name. On Linux, mold is
the linker on both sides of the cache: the builders pin `-fuse-ld=mold`,
and a Linux build without mold does not start — a fallback would produce
artifacts keyed for a linker the cache does not publish. Which linker a
target uses by default is never observed or relied on.

Identity components are typed newtypes (`types/src/identity.rs`):
`CrateName`, `CrateVersion` (strict semver), `FeaturesJson` (strictly
sorted, deduplicated), `TargetTriple`, `WireRustcVersion`, `CMetadata`
(1–64 hex), `DependencyCMetadataJson`. They are validated at
deserialization, so no handler validates by hand.

## The CLI

### A build

`stow build` (and `check`, `test`) resolves the project, starts a per-build
supervisor, and runs cargo with the stow wrapper as `RUSTC_WRAPPER`. Before
cargo starts it spends a bounded pre-cargo budget on graph analysis and
prefetch; whatever the budget does not cover is fetched on demand by the
wrapper. In parallel, a background enrichment fetches the index slices
and writes the per-build allow markers that say which crates are worth a
remote lookup.

For each rustc invocation the wrapper:

1. Parses the invocation and derives its stable identity.
2. Looks the identity up in the local cache. A local hit is served with no
   network.
3. If the crate has an allow marker and the circuit is closed, resolves
   the identity against the verified index slice, fetches the bundle by
   digest, verifies it, and injects the outputs into cargo's target
   directory.
4. Otherwise runs rustc, stores the outputs in the local cache, and
   journals the unit as an observed miss.

After cargo exits, the journal's observations become misses reported to
the edge (below). The supervisor holds one edge connection for the build
rather than one per invocation.

### Resolution against the signed index

The CLI never asks a server what is cached. It pulls the signed index
slice for `(target, rustc)` from GHCR, verifies the signature, caches the
verified blob under `<cache_dir>/index/<target>/<rustc>/`, and resolves
every key locally: exact match, semver-compatible upgrade, feature
containment, profile, emit and kind checks. A slice younger than
`STOW_INDEX_REFRESH_SECS` short-circuits the network; past it one manifest
request revalidates the digest, and only a moved digest costs a download.
When the consumer's host triple differs from the target, the host slice is
fetched too, since host units resolve against it.

The dependency graph therefore stays on the machine. It leaves only as the
misses and inexact hits the CLI reports.

### Reporting misses

A miss is reported only for a unit this build actually compiled, at the
identity its rustc invocation used: the argv's cfg feature set, the real
platform (the host triple for host units) and each `--extern`'s recorded
identity. A compile is the proof behind the report — nobody pays a full
compile to lie about what they need.

1. The CLI posts the observed graph to `POST /api/v1/admissions` with its
   source (`miss` or `inexact_hit`).
2. The edge turns the posted unit graph into one submission tree and mints
   a stateless admission: the canonical tree, an HMAC-SHA256 challenge over
   `task_id ‖ canonical tree JSON ‖ issue_minute`, and a proof-of-work
   difficulty of `STOW_POW_MIN_BITS` leading zero bits.
3. The CLI solves `blake3(task_id ‖ challenge ‖ nonce)` and posts the
   ticket to `POST /api/v1/enqueue`, which recomputes the challenge
   (valid in its issue minute and the next), checks the work, and forwards
   the tree to the scheduler's CLI entry point.

Nothing is stored per admission; a forged or altered tree cannot verify.
A consumer target outside `CI_TARGET_TRIPLES` reports nothing — no runner
could build it. A report that cannot be redeemed stays in the journal and
is retried with a fresh challenge by a later build.

Proof-of-work is a cost floor, not the defence: a legitimate client and an
attacker pay the same price per request. At 12 bits it is about 0.27 ms at
the measured 66 ns per hash. Difficulty once rose with queue depth; that
charged whoever arrived next for a backlog everyone built — a warm build
spent 342 CPU-seconds mining against 44.6 to compile the project — and was
removed. The defences are, in order: the zone's IP rate-limit rule (zone
configuration, outside this repository), the scheduler's pending cap
(`STOW_MAX_QUEUE_PENDING`), identity canonicalization (a client cannot mint
identities from arbitrary strings, so every task it can create is one a
real user could hit), and the zone maintenance rules.

There is no user-facing preheat. A miss costs a compile and the website
costs a human check; a command that enqueued arbitrary graphs for 270 µs of
hashing would let anyone push real misses behind speculative ones.
Preheating on someone else's behalf is an operator lane.

### The local cache

The CLI is a full replacement for sccache. Every bundle it fetches and
every unit it compiles that the cache can key is kept in one global
copy-on-write cache under `<cache_dir>/cache/<rustc>/`, shared by every
project and worktree on the machine. The next worktree, `cargo clean`,
branch switch or unrelated project with the same dependency hits it with
no network.

- **Shared identity.** A local entry is stored under the same compile key
  and `c_metadata` a remote bundle carries
  (`bundles/v3/<target>/<c_metadata>`), so local and remote entries are one
  key space. A remote download that finds a local entry for its identity
  keeps the local one.
- **What is stored today.** Clean compiles (rustc exit 0, every expected
  output present) of crates.io registry units producing an rlib, dylib or
  proc-macro, with `-C metadata` and `--out-dir`, and no custom codegen.
  Workspace members, path and git dependencies, `staticlib`, binaries and
  build-script runs are not stored. Dev and release profiles are both
  eligible. A build script's `OUT_DIR` products are not needed: the unit is
  served inside a rustc invocation cargo issued after running the script.
- **Copy-on-write.** Outputs move in and out with `reflink_or_copy`: a
  reflink on APFS, Btrfs, XFS and ReFS, a copy elsewhere.
- **Crash safety.** Each storing process stages under
  `<rustc>/staging/<name>/` beside a `<name>.lock` it holds for its life,
  hashes the staged bytes, and renames the entry into place under an
  exclusive entry lock. A killed process leaves its staging directory and
  lock; the next build reclaims every lock it can acquire and leaves held
  ones alone.
- **Trust.** A local entry was produced by this machine's rustc, so it is
  trusted by construction: it is never signature-checked, never carries a
  verified marker and is never uploaded. Provenance (`remote`/`local`) is a
  typed column; an unknown value fails the read.
- **Eviction.** One LRU over both provenances, bounded by
  `STOW_ARTIFACT_CACHE_MAX_BYTES` (default 20 GiB). Every hit bumps the
  entry's access time.
- **One rustc at a time.** The cache is partitioned by rustc version. When
  a build runs under a rustc other than the last one recorded, it moves
  every other version's directory to `<cache_dir>/purge/` (skipping
  versions another running build holds a lease on) and deletes it.
  Alternating toolchains therefore starts each switch cold.

### Offline

With GHCR or the edge unreachable, a build serves and stores locally:
local entries are looked up before any remote serve, and the
post-compile store needs no network. An index fetch that fails with a
cached slice serves the cached slice. The circuit breaker
(`circuit_trip_threshold` consecutive failures, reset after
`circuit_reset_secs`) stops remote fetches but never local hits. Misses
that cannot be reported stay in the journal for a later build.

Where it is slower than it should be: with no cached slice, units that
miss locally wait for the background index fetch to give up — the OCI
client retries a refused connection with backoff — and with a cached slice
each unit already fetching waits out its request timeout before the
breaker trips. The build completes; it does not degrade to local-only at
once.

### Verifying an artifact

Every remote hit is verified before a byte reaches cargo's target
directory (`cli/src/verify.rs`):

- the bundle bytes must hash to the index row's `bundle_digest`;
- the signature material must carry a Rekor bundle whose signed entry
  timestamp verifies against the Rekor log key;
- the `hashedrekord` body must record this signature, this certificate
  (compared as DER) and the SHA-256 of this payload;
- the Fulcio chain and the certificate's validity window are evaluated at
  the entry's integrated time;
- the certificate's SAN and OIDC issuer must equal
  `https://github.com/water-rs/stow/.github/workflows/build-crate.yml@refs/heads/main`
  and `https://token.actions.githubusercontent.com`
  (`types/src/trusted_builder.rs`);
- only then is the ECDSA signature over the payload checked.

A key leaked from a short-lived Fulcio certificate cannot sign anything
after the certificate expires. A failure is a local compile, never an
error and never a served artifact. Index slices are verified the same way
against `index-publish.yml@refs/heads/main`. Bundle file names are checked
against the declared set and rooted paths are refused before anything is
written.

## The resolver

`stow-resolver` turns names into nodes: a crates.io crate at a version, a
`.crate` tarball, or a GitHub project fetched as a tree. It materializes
the source in a temp directory under an isolated `CARGO_HOME`, drops the
bundled lockfile (registry pins stay admissible when yanked, git pins lock
to the recorded sha), selects versions once, and projects the selection
onto each of `CI_TARGET_TRIPLES` with cargo's own `FeatureResolver`, using
the real `rustc -vV` and `rustc --print cfg --target <t>` of the pinned
toolchain. Dev-dependencies are never resolved. The output is a task graph
— nodes with their dependency digests and edges — shaped for submission.

It runs where cargo and a real toolchain exist: in `stow-admin` on an
operator's machine and on GitHub Actions runners (preheat lanes, the
website's resolve job). Never in the edge. Resolving in the Worker was
tried and failed on CPU, the 128 MiB isolate cap and per-request limits
for large projects, and needed a vendored copy of cargo's resolver kept in
sync by hand.

The CLI does not run the resolver: cargo has already resolved the user's
build, and the CLI reads cargo's own unit graph.

## The edge

The edge (`edge/`, deployed as a Worker on `stow.waterui.dev`) is the
public entry point and keeps no database. It:

- **Streams bundles.** `GET /api/v1/bundles/{rustc}/{digest}` validates the
  `sha256:<64 hex>` digest and hands workerd the GHCR response stream
  itself, so the bytes never enter wasm, with an immutable
  `Cache-Control`. Workers Cache serves every repeat without the Worker
  running. No catalog row is consulted: the CLI's signed index named the
  digest and the CLI verifies the bytes. Index slices are served the same
  way for the website's in-browser lookup
  (`/api/v1/index/{target}/{rustc}[/{digest}]`).
- **Caches crates.io answers** (versions, features, search, the stable
  channel manifest) in the Workers Cache API.
- **Mints and redeems miss admissions** (above). The admission handler
  converts the posted unit graph into a submission tree; it resolves
  nothing against crates.io.
- **Takes website requests.** `POST /api/v1/requests` verifies a Turnstile
  token and hands the request to the scheduler, which dispatches a
  `resolve-request.yml` run to resolve it.
- **Receives webhooks** and forwards what the scheduler consumes (below).
- **Serves the operator API** under `/api/v1/admin/*` and
  `/api/v1/scheduler/*` to GitHub-authenticated callers.
- **Writes usage statistics** to Analytics Engine.

The edge is untrusted serving infrastructure. It holds no signing
identity and cannot make the CLI accept a byte; a compromised edge can
deny service and lie about the queue, nothing more.

### Webhook forwarding

`POST /api/v1/github/workflow-run` authenticates GitHub's `workflow_run`
delivery by its `X-Hub-Signature-256` HMAC over the raw body. A run is
consumed only when it is `build-crate.yml` or `resolve-request.yml`, on
`main`, dispatched by `workflow_dispatch`, in `water-rs/stow` (head repo
equal to event repo, so a fork cannot pose as upstream), with a `run-name`
that parses. It forwards:

- a `build-crate.yml` `completed` — every one, whoever dispatched it,
  because the delivery is what frees the slot. A `success` counts only
  once the run's signed records artifact exists in GHCR; the edge checks
  that first, and forwards a registry error as "unverified" rather than
  dropping the completion. Its title `<rustc>-<task_id>` names the node.
- a `build-crate.yml` `in_progress` only for a run the scheduler did not
  dispatch (one whose triggering actor is not the `stow-ci` App's bot);
  the scheduler learns its own runs' state from the CI listing.
- a `resolve-request.yml` `in_progress`, and its `completed` only when the
  run did not succeed — a successful run already posted its outcome.

GitHub never redelivers a failed delivery on its own, so nothing relies on
redelivery; stale-lease recovery reclaims a node whose completion was lost.

`POST /api/v1/newreleases/release` takes newreleases.io's delivery for a
new `rust-lang/rust` release (HMAC over `<timestamp>.<body>`, 300 s
tolerance) and forwards the claimed version; the scheduler dispatches
`preheat-admin.yml`, which confirms the version against the official
channel manifest before resolving, so a forged delivery costs one manifest
check.

## The CI interface

One privileged interface reaches GitHub Actions for builds
(`types/src/ci.rs`, `CiInterface`). It has two operations:

- **status** — `build-crate.yml` runs `queued` and `in_progress`, counted
  per runner family (Linux, macOS, Windows). A run's family is read from
  its title: the task id carries its target. Two listing calls plus one
  per page past 100 runs.
- **submit** — one `workflow_dispatch` of `build-crate.yml` on `main` for
  one task, returning the run id GitHub assigns.

It is FIFO and never reorders: calls go out in the order made, and
priority is not its concern. It holds no state; an endpoint (GitHub under
the `stow-ci` App installation token, or the mock stack's local CI server
on the same paths) and a transport are its whole context. Only operations
tooling and the scheduler use it.

Runner capacity is shared with every other repository in the
organisation, which stow cannot count. Of the org's 60 runners (20 macOS)
stow takes at most 45 (16 macOS) by default — `STOW_MAX_CONCURRENT_JOBS`
and `STOW_MAX_CONCURRENT_MACOS_JOBS`.

Batched dispatch existed once: up to 40 tasks in one run. GitHub reports
one completion per run, so every dependent of a batch leg waited for the
slowest leg. One task is one run, and dispatch is never batched.

## The scheduler

The scheduler is one Durable Object instance holding the whole dependency
graph in memory (`edge/src/scheduler/`). There is one, not a shard per
target or lane, because priority and capacity are global and dependency
edges cross targets.

### State

Nodes, edges, per-node state and the ready set live in memory, laid out
for the 128 MiB object bound: a node is a fixed 68-byte arena record with
interned strings and an inline dependency digest; its task id is re-minted
from those fields, never stored; queue state rides a 48-byte slab entry
freed on publish; edges are flat `u32` arrays with a reverse index. A
published node stays only while a retained node depends on it and is
dropped with its edges after that.

A Durable Object gets no callback before eviction and loses memory after
about ten idle seconds or on a deploy. So the store is flat:

- `event_log` — every accepted event is appended, stamped with its
  acceptance instant, before the request is acknowledged.
- `snapshot_chunks` and `store_meta` — a snapshot is written in large
  chunks when 8192 events or 8 MiB have accumulated, then the watermark,
  then the covered log rows are dropped. The drop is the commit point; a
  crash mid-snapshot replays the old snapshot plus the full log.

A wake loads the latest snapshot, replays the log tail at each event's own
instant, rebuilds every derived index, and then reconciles against the CI
interface's status listing: a listed run whose title names a claim with no
bound run re-binds it, and a listed run nobody claimed counts as external
occupancy.

Modelling the graph as SQL rows — an indexed row per task, a row per
edge, counters on every owner — cost about 47 rows written and 1.7
Durable Object requests per task, with costs that grew with the stored
graph. Memory plus a flat log makes each event's cost a function of the
event.

### Entry points and priority

Each source submits one dependency tree per source (a project, a crate, a
miss) with each node once; the scheduler merges it into the graph by task
id. Priority belongs to the entry point, not the node:

| Entry point | Admission | Priority |
|---|---|---|
| operations (`stow-admin submit`, `preheat manual`) | GitHub push access or a repo workflow's OIDC token | set by the caller (`--priority`, in multiples of the CLI miss) |
| CLI miss | proof of work | 1× — 100 in the internal centi-units |
| CLI inexact-hit report | proof of work | 0.01× |
| stow.waterui.dev | Turnstile and a daily budget | 30× |
| preheat | repo workflow OIDC | 0.1× |

A ready node's rank is its priority times the time it has waited since it
was first requested; ties go to the earlier first request, then the
earlier arrival. A higher priority is a shorter wait, not precedence, so
nothing starves: a website request that has waited two minutes ranks with
a CLI miss that has waited an hour, and an old preheat node eventually
outranks a fresh miss. A node reached from several entry points keeps the
highest priority and its first-request time. The claim is a k-way merge
over priority classes, each class ordered oldest first, so picking the
next node never re-ranks the ready set.

`STOW_MIN_DISPATCH_VALUE` is an admission floor on the priority operand;
under-floor work stays queued and visible. `STOW_DISPATCH_MIN_AGE_MINUTES`
delays the alarm wake for a newly requested node so identical misses can
coalesce; it gates only the alarm's timing, so a pass triggered by
another event claims the node at once. Website nodes are exempt from
both.

Admission bounds per entry point: CLI misses are refused with 429 once
`STOW_MAX_QUEUE_PENDING` nodes are pending (checked by the edge and again
inside the object); website requests are capped per target closure
(`STOW_HUMAN_MAX_CLOSURE`, checked in the resolve job) and per UTC day
(`STOW_HUMAN_DAILY_TASK_BUDGET`). Operations and preheat submissions are
exempt from the pending cap.

### Dispatch

The scheduler fills free capacity in rank order, never more than the free
count, so GitHub's own queue stays shallow. A pass runs on the events that
change the answer: a submission, a completion (inline, inside the webhook
request), a slice report, and the alarm. The alarm wakes only for timed
work — a retry backoff expiring, a lease expiring, an age hold ending, or
the status reconcile, which runs at most every ten minutes and only while
the graph holds in-flight or dispatchable work. An idle scheduler has no
alarm.

Each claim mints a generation and dispatches through the CI interface's
submit; the returned run id is bound to the claim, so a completion settles
only the run that claim started. A claim whose run is still listed keeps
its lease however long the build runs; a claim with no listed run returns
to pending after `STOW_STALE_DISPATCH_MINUTES`.

The dependency gate reads the scheduler's published mask. `index-publish`
reports each slice it pushed (`POST /api/v1/admin/index/published`) with
the identities it added and retired, and a dependent claims only when
every edge resolves to a published shape in its dependency's own
`(target, rustc)` slice. At claim time a node whose exact identity is
already published retires as completed without a build.

### Failure

A failed build retries under `not_before = now + 2^min(attempt, 6)`
minutes, capped at 60, up to four attempts. At the cap it parks `failed`;
its dependents never open and read as `blocked` by it. Re-submissions do
not resurrect a failed node: at a fixed identity a deterministic failure
cannot succeed on retry. `stow-admin queue retry` resets the cycle after a
builder fix.

### Dispatch freeze

The object freezes its own dispatch on two trips, evaluated on the events
that change their inputs, never on a timer:

- **Failure rate.** Each completion updates a five-minute outcome bucket
  per target. Over the trailing `STOW_FREEZE_WINDOW_MINUTES`, a stream —
  the fleet or one target — trips when it has at least
  `STOW_FREEZE_MIN_OUTCOMES` outcomes *and* at least
  `STOW_FREEZE_FAIL_PERCENT` failed. A bare ratio false-positives on small
  samples; a bare count trips constantly at volume.
- **Cost.** A metering wrapper reads `rowsRead`/`rowsWritten` off every
  statement's cursor — the counters Cloudflare bills — into a day meter
  checkpointed at each wake and snapshot. The day's budget is 80% of the
  monthly Workers Paid allowance / 30 × `STOW_COST_BUDGET_MULTIPLIER`; the
  operation that crosses it freezes dispatch.

While frozen the queue keeps accepting misses, the work-submitting routes
answer 503 naming the trigger, and completions keep landing. Recovery is
manual: `stow-admin dispatch-freeze clear --yes`. Each transition sends
one email and keeps an `incident` issue (see [Operations](#operations)).

### Schema

The object's store has one schema, `edge/src/scheduler/schema.sql`. Only
the operator reset (`stow-admin scheduler reset --yes` →
`POST /api/v1/admin/scheduler/reset`) issues DDL: it drops every store
object, re-executes the file and clears the alarm. Request code and the
alarm never create, alter or backfill; a store nobody reset fails on its
first read. A schema change is a reset, and the graph refills from the
lanes that feed it. The object persists nothing outside its SQLite store,
so no change to its Rust fields can lock it out of its own state.

## Building a node: `build-crate.yml`

One run builds one node. `run-name` is `<rustc>-<task_id>`; the task, with
its node and its dependency subtree, is the `task` input. The subtree pins
what the node is built against. A concurrency group keyed by the task id
serializes duplicates without cancelling, and a run whose signed records
already exist exits. Jobs run on the target's runner family (Ubuntu,
macOS 14, Windows), with all third-party code in the first.

### `build` job — untrusted

`permissions: contents: read` and `packages: read`; no secrets, no
`id-token`. It runs `stow-build build`:

- `cargo fetch` resolves and downloads on the host; each cargo phase
  (`check`, then `build`) then runs `--offline` inside a `heel` sandbox:
  empty environment, no home directory, a deny-by-default filesystem with
  explicit grants (toolchain and cargo homes, registry sources read-only,
  the phase's target directory — outside the sandbox working directory,
  which never executes), and every connection proxied and audited into
  `network-audit.jsonl`.
- On the host, before the sandbox starts, the build pulls the signed index
  slice and every dependency bundle in the subtree straight from GHCR by
  digest, verified like any CLI hit, and stages them read-only for the
  wrapper to inject. A slice that cannot be read fails the build: the node
  was dispatched because its dependencies are published, and a build that
  cannot see them would compile its whole closure.
- The rustc wrapper sends one capture record per wrapped invocation, with
  the SHA-256 of every output taken as rustc exited, over heel's IPC
  channel to a host-side collector keyed on unit identity; a second record
  for an identity aborts the stage. The scan re-hashes the bytes it plans
  and aborts on any mismatch, so a later build script cannot rewrite an
  earlier output into the plan.
- A host-side node compiles as a `[build-dependencies]` unit of the
  wrapper and runs each phase under both the native and the explicit
  `--target` spelling, publishing both shapes.
- The output — task, plan, content-addressed blobs — is uploaded as a
  workflow artifact.

A malicious `build.rs` or proc-macro can neither push to GHCR nor mint an
OIDC token Fulcio would sign. What remains: it can produce arbitrary bytes
for its own crate — the signature attests "built by the pipeline for task
T", nothing more — and heel grants `/proc`, `/sys`, `/etc` and `/run` read
on Linux and `sysctl-read` on macOS, so sandboxed code can read other
same-UID processes' environments, including the runner's
`ACTIONS_RUNTIME_TOKEN`. Narrowing that is a heel grant change.

### `publish` job — trusted

`packages: write` and `id-token: write`. It runs `stow-build publish` and
believes nothing the build job says:

- the task comes from the dispatch event (`GITHUB_EVENT_PATH`), and the
  build output's copy must equal it;
- every blob is re-hashed against the plan;
- every planned artifact's target and rustc equal the task's;
- every planned `(crate, version)` is in the closure the publisher computes
  itself from a fresh crates.io download with `cargo --unit-graph`, which
  plans and never executes crate code. Dev-dependencies and other
  platforms' dependencies are never compiled, so a plan entry for one is a
  fabrication;
- every `oci_reference` equals the one the artifact's identity produces.

It then pushes each artifact's signed image and its `.bundle`, and a
cosign-signed `records-<rustc>-<task hash>-<run_id>-<run_attempt>`
artifact naming what it published. Completion reaches the scheduler
through GitHub's webhook; the build path never calls the edge.

### OCI layout

Every artifact lives in its rustc's GHCR package,
`ghcr.io/water-rs/stow-cache-<rustc>`, tagged
`{crate}.{version}-{target_short}-{rustc_short}-{feat_hash}-{c_metadata}{kind_suffix}`
(`types/src/registry.rs`). The crate name is the first `.`-separated
segment, unambiguous because crates.io names never contain `.`.

- The signed image: config `ArtifactBlobConfig`, one zstd layer per output
  file plus the native `OUT_DIR` archive when the build script produced
  one. Cosign signs this image.
- `<tag>.bundle`: one layer, the tar the CLI consumes
  (`stow_types::bundle::assemble_bundle`). It embeds the signed manifest,
  config and signature material byte-for-byte, so it needs no signature of
  its own. Its digest and size are recorded as `bundle_digest` and
  `bundle_size` and republished in the index row.

| Bundle path | Content |
|---|---|
| `manifest.json` | `ArtifactBundleManifest`: OCI reference and digest, embedded `ArtifactBlobConfig`, sigstore signatures |
| `oci/manifest.json` | The signed image's OCI manifest, registry bytes verbatim |
| `oci/config.json` | The signed image's config, registry bytes verbatim |
| `sigstore/payload-<n>.json` | Cosign simple-signing payloads, one per signature layer |
| `files/<name>` | One entry per layer: `.rlib`, `.rmeta`, `.so`/`.dylib`/`.dll`, the native archive |

One package per rustc keeps each package listable and makes retirement one
delete: a retired rustc's package is deleted whole, and stow never deletes
single versions. A new rustc's package is created by its first build push
from `build-crate.yml`'s `GITHUB_TOKEN`, which links it to `water-rs/stow`
and inherits its public visibility, so no manual step opens one. Until it
exists GHCR answers an anonymous pull with `403 DENIED`; every reader
treats that as the empty index.

## Publishing the index: `index-publish.yml`

The index is the only catalog. One signed slice exists per
`(target, rustc)`: `index.<target>.<rustc>` on the rustc's package, a
single zstd JSON layer (`application/vnd.stow.index.v1+zstd`) whose typed
header pins `format_version` and a `row_count` checked against the body
(`types/src/index.rs`). A row carries the identity, `dependency_c_metadata_json`,
`dependency_task_ids`, `c_metadata`, `compile_key`, `bundle_digest`,
`bundle_size`, kind, crate types, profile, emit, unit shape and the
minimum glibc it needs.

`index-publish.yml` folds signed records into slices:

1. `stow-admin index export --rustc-version` pulls and verifies the
   published `index` and `folded` pair of every slice of that rustc, then
   only the `records-<rustc>-*` artifacts no folded set covers, all from
   GHCR, and verifies each signature against `build-crate.yml@main`.
2. A slice whose `content_sha256` (everything but the `generated_at`
   timestamp) equals the published manifest's
   `dev.stow.index.content-sha256` annotation is skipped, so an unchanged
   slice never churns its tag.
3. `stow-admin index publish` pushes each changed `index` and `folded`
   pair and cosign-signs both under `index-publish.yml@refs/heads/main`.
4. With `stow_edge_url` set, the run reports each slice's added and
   retired identities to the scheduler in one call.

Every target in `CI_TARGET_TRIPLES` gets a slice, empty if nothing is
built, so a `--target` consumer always finds the tag. `full=true` rebuilds
a rustc's slices from every records artifact.

Scheduled and `workflow_run` workflows run on the default branch, `dev`,
whose identity the CLI rejects. So `index-publish.yml` is dispatch-only
and refuses any ref but `main`, and `index-publish-cron.yml` dispatches it
on `main` after every completed `build-crate` run, with a ten-minute
schedule as the backstop.

## Preheat

The identity pins the exact rustc, so every stable release empties the
pool, and the top of crates.io moves daily. Preheat fills the pool before
anyone misses. It resolves on GitHub-hosted runners — resolution needs
cargo and real rustc facts, so it runs on a machine — and submits one
dependency tree per source to the scheduler's preheat entry point. It
never dispatches builds itself.

- **On a release.** newreleases.io reports the release to the edge; the
  scheduler dispatches `preheat-admin.yml`, which confirms the version
  against `channel-rust-stable.toml` and runs the wave.
- **Daily.** `preheat-cron.yml` reads the stable channel and dispatches
  `preheat-admin.yml` once per UTC day; an `actions/cache` marker keyed by
  version and day makes reruns no-ops.
- **The wave.** `preheat-admin.yml` runs `stow-admin preheat top-binaries`
  — the top crates by 90-day downloads whose default version ships a
  binary and no library, read from the crates.io database dump, each
  resolved as a name source — and `stow-admin preheat projects submit`,
  which resolves every repository in the reviewed `preheat/projects.toml`.
- **The project list.** `preheat-projects.yml` (weekly) runs
  `stow-admin preheat projects generate` against GitHub's most-starred
  Rust repositories and opens the diff as a pull request; the wave reads
  only the merged file.
- **Observed demand.** `preheat-missed.yml` (weekly) submits the most-missed
  identities from the `stow_cache_misses` dataset. `demand-feed.yml`
  (hourly) runs `stow-admin scheduler demand-feed`, which stages the
  closed hour's misses as pages and delivers them to the scheduler under a
  durable cursor, so a failed job resumes on the next tick.

Re-submitting a whole wave is cheap by construction: the merge is by task
id, completed and published nodes stay so, and the scheduler builds only
what is missing.

## Website requests

A person asks for one crate on stow.waterui.dev. `POST /api/v1/requests`
verifies the Turnstile token, resolves the version (newest non-yanked
release when omitted) and the current stable rustc (cached in the Cache API
for an hour), and hands the request to the scheduler, which records it
`accepted` and dispatches `resolve-request.yml` through the CI
interface. That job runs `stow-admin request resolve`: it resolves the
closure on every CI target, prunes it against the published slices,
enforces `STOW_HUMAN_MAX_CLOSURE`, and posts the plan to
`/api/v1/scheduler/requests/{id}/outcome`, which enqueues the uncovered
nodes at website priority and marks the record `enqueued`.
`GET /api/v1/requests/{id}` and the `/requests/{id}` page follow the record
through `accepted` → `resolving` → `enqueued`/`failed` and then each
target's state until everything is cached. The requested crate is a name
source: if it is bin-only, its libraries are what gets built.

## Trust

- **GitHub-hosted CI is the only builder.** Only
  `build-crate.yml@refs/heads/main` in `water-rs/stow` signs artifacts and
  only `index-publish.yml@refs/heads/main` signs index slices; the CLI
  accepts nothing else. The build path never calls the edge.
- **crates.io is the only metadata source.** Builders download crates
  from crates.io, the publisher computes the closure from a fresh crates.io
  download, and resolution reads crates.io.
- **GHCR records are the only record store.** Signed records in GHCR are
  the truth; the index is folded from them, and anything else that holds
  rows is a mirror. Every reader verifies the signature before trusting a
  row. The `index` and `folded` pair can be rebuilt from the records at any
  time.
- **The edge is untrusted serving infrastructure.** It streams bytes the
  CLI verifies, holds no signing identity, and its GitHub App token
  carries no `issues` grant. Its compromise costs availability and queue
  integrity, not artifact integrity.
- **Operators are untrusted for artifacts.** No operator credential signs
  anything: an operator can reset the queue, submit tasks, freeze dispatch
  or shed traffic, but cannot make the CLI accept a byte. The trusted
  routes authorize by GitHub identity on `Authorization: Bearer` — an
  Actions OIDC token minted in `water-rs/stow` (RS256 against GitHub's
  JWKS, with `iss`, `aud`, `repository`, the workflow-ref prefix and `exp`
  pinned) or any credential GitHub would accept a push from, probed through
  the `git-receive-pack` advertisement. No shared secret exists to leak.
  Outside Actions, `stow-admin` sends only the `stow-ci` App user token
  from `stow-admin login` (eight-hour expiry, kept in the OS credential
  store) or an explicit `GH_TOKEN`/`GITHUB_TOKEN`. The WAF toggle runs
  as `maintenance.yml`, so every toggle is a recorded Actions run under a
  GitHub account with the repository's Cloudflare secret, and no operator
  holds a Cloudflare token.

Hops and what each may do:

| Hop | Reads | Writes |
|---|---|---|
| CLI | GHCR signed index slices; bundles through the edge byte path | local cache; miss reports through admissions and enqueue |
| Edge | GHCR, crates.io, Analytics Engine SQL | scheduler (forwarded submissions and deliveries); Analytics Engine points |
| Scheduler | its SQLite store; the CI interface's status | its store; `workflow_dispatch` of `build-crate.yml`, `resolve-request.yml` and `preheat-admin.yml` on `main` |
| `stow-build build` | crates.io, cache bundles, the task | its output directory |
| `stow-build publish` | the build output, the dispatch event, crates.io | GHCR artifacts, bundles, records; sigstore signatures |
| `index-publish.yml` | GHCR records and published slices | `index.*`/`folded.*` tags and signatures; the scheduler's published mask |

## Operations

### Shedding traffic

Cloudflare has no spend cap, so the zone's WAF custom rules stop traffic
before the Worker runs. Three rules live on the `waterui.dev` zone,
created disabled by `stow-admin maintenance ensure` on each deploy and
matched by description so a redeploy never resets a live toggle:

| Rule | Blocks |
|---|---|
| `stow maintenance: anonymous` | every route on the edge host except `/api/v1/admin/*`, `/api/v1/scheduler/*` and `/api/v1/github/*` |
| `stow maintenance: scheduler lanes` | exactly the public routes that reach the scheduler (`scheduler_lanes` in `types/src/api.rs`), so bundle bytes keep serving |
| `stow maintenance: all` | the whole hostname |

A blocked request is answered in the security phase: no Worker
invocation, no Durable Object work. The trusted prefixes and the webhook
stay up under `anonymous`, so completions drain and the operator can turn
the rule back off. Building the breaker inside the Worker would cost an
invocation per shed request and fail closed on a storage error.

### Watchdog, alerts and the digest

`watchdog.yml` runs `stow-admin watchdog` every 15 minutes from the
signed toolchain. It reads Cloudflare usage over GraphQL against each
product's hourly share of the monthly allowance, edge health (5xx rate,
exceeded CPU or memory, overloaded Durable Object answers), the build
pipeline (failure rate by class and target, attempts, oldest pending,
stalled dispatch) and the public endpoints. On a cost, resource or
failure-rate breach it trips: it disables `build-crate.yml` and the
preheat and index-publish-cron workflows and enables the `anonymous` rule.
It runs outside the edge, so a broken edge cannot silence it.
`stow-admin watchdog clear` is the manual recovery.

Every alert, breaker trip and watchdog report sends an email from
`alerts@stow.waterui.dev` and keeps an `incident`-labelled issue; either
channel failing never stops the other. The edge sends the dispatch-freeze
transition mail through its `send_email` binding; the watchdog writes and
closes the issue, since the edge's token has no `issues` grant.

`build-failure-digest.yml` runs `stow-admin builds digest` daily: the
previous 24 hours' failed `build-crate.yml` runs, classified by the step
each died in, posted as one comment on the single open `Daily failed
builds` issue, which a clean day closes. It sends no mail.

### Cost

Every Cloudflare resource stays under 80% of its monthly Workers Paid
allowance, and every residual cost is treated as part of the product.
What keeps it there:

- Request code and the alarm do work proportional to the event, never to
  stored data; idle cost is zero. Each scheduler route and the alarm has a
  drive in `edge/src/scheduler/drives.rs`, and `scripts/traffic-cost.sh`
  gates their rows read and written at production-shaped sizes and the
  projected month at launch traffic.
- Bundle and index bytes pass through without entering wasm — copying
  them cost about 63 ms CPU per bundle — and Workers Cache replays them
  without running the Worker.
- One completion is one Durable Object request: the scheduler's own runs'
  `in_progress` deliveries are not forwarded, and dispatch runs inline in
  the completion rather than on a separate alarm.
- D1 was removed. Coverage comes from the scheduler's published mask and
  the signed index; crates.io answers live in the Cache API.

## Usage statistics

Two Analytics Engine datasets (`edge/src/stats.rs`). Points carry no IP
address, request id, dependency graph or lockfile; installs are counted by
a daily-salted hash (`STOW_STATS_SALT_SECRET`) that cannot be joined
across days; small counts are never published. `STOW_NO_ANALYTICS=1`
makes the CLI send `x-stow-no-analytics: 1` on every request and no build
report at all, and every write takes that consent as an argument.

- `stow_cache_misses` (`STOW_ANALYTICS`): one `graph` miss point per node
  of a redeemed ticket that the scheduler's merge found unpublished,
  carrying the artifact identity. An admission that is never redeemed
  writes nothing.
- `stow_events` (`STOW_STATS`): `hit` — one per bundle fetch the platform
  cache let through to the Worker, with the digest and request dimensions
  (rustc, CLI version, OS, country, CI/local); a lower bound by design,
  resolved to identities offline by `stow-admin index join` — and `build`,
  one per accepted `POST /api/v1/build-report`, the at-most-daily counters
  an install posts.

`GET /api/v1/stats` and the `/stats` page run `edge/src/sql/stats_*.sql`
against the Analytics Engine SQL API, cached for an hour.
[PRIVACY.md](../PRIVACY.md) is the data contract.

## HTTP surface

All routes are on the edge. Trusted routes authenticate the bearer before
the body is parsed. `/api/v1/` sits behind the zone rate-limit rule (60
requests per 10 s per IP over the prefix) except `/api/v1/bundles/`, where
one build legitimately sends tens of requests a second and a cache hit
costs only the billed request.

| Method and path | Auth | Purpose |
|---|---|---|
| GET `/`, `/stats`, `/requests/{id}` | none | Site pages |
| GET `/install.sh`, `/install.ps1` | none | Installer scripts |
| GET `/api/v1/bundles/{rustc}/{digest}` | none | Bundle bytes, streamed from GHCR |
| GET `/api/v1/index/{target}/{rustc}` | none | The digest the slice tag names |
| GET `/api/v1/index/{target}/{rustc}/{digest}` | none | Slice bytes, for the website's browser lookup |
| GET `/api/v1/crates/search`, `/api/v1/crates/{name}/versions`, `/api/v1/crates/{name}/versions/{version}/features` | none | crates.io answers for the request form |
| POST `/api/v1/admissions` | none | Mint a miss or inexact-hit admission |
| POST `/api/v1/enqueue` | challenge + proof of work | Redeem an admission |
| POST `/api/v1/requests` | Turnstile | Website request |
| GET `/api/v1/requests/{id}` | none | Request status |
| POST `/api/v1/build-report` | none | Daily usage counters |
| GET `/api/v1/stats` | none | Usage statistics |
| POST `/api/v1/github/workflow-run` | GitHub HMAC | `workflow_run` deliveries |
| POST `/api/v1/newreleases/release` | newreleases.io HMAC | Rust release deliveries |
| GET `/api/v1/scheduler/status`, `/api/v1/scheduler/health` | none | Queue depths; uncached liveness (503 when unhealthy) |
| POST `/api/v1/scheduler/tasks/submit`, `/api/v1/scheduler/tasks/submit-ids` | bearer | Submit trees; re-submit known nodes by id |
| POST `/api/v1/scheduler/requests/{id}/outcome` | bearer | The resolve job's outcome |
| GET `/api/v1/admin/status` | bearer | Operator view of the scheduler |
| GET `/api/v1/admin/queue`; POST `/api/v1/admin/queue/{retry,cancel,promote,purge}` | bearer | Queue reads and transitions |
| GET, POST `/api/v1/admin/dispatch-freeze` | bearer | Read, engage or clear the freeze |
| POST `/api/v1/admin/index/published` | bearer | index-publish's slice report |
| POST `/api/v1/admin/scheduler/reset` | bearer | Store reset |
| POST `/api/v1/admin/scheduler/demand`, `/api/v1/admin/scheduler/demand-feed/*` | bearer | Demand feed |
| `/api/v1/admin/scheduler/budget[/seed,/rearm,/ledger]` | bearer | Cost probe; answers only on mock deploys |

## Local development

- `cd edge && cargo check` builds the Worker for `wasm32-unknown-unknown`;
  from the root, `cargo check` covers the host half.
- `STOW_TRACE_FILE=<path> stow check` writes a Chrome-format trace of
  every `stow.*` span.
- `stow-build serve --listen 127.0.0.1:7000` starts the local CI server
  the mock stack dispatches to.
- [MOCK.md](MOCK.md) describes the local mock stack every change is
  verified on.
