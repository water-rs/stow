# Stow Architecture

This document spells out the protocols, schemas, and invariants that the
high-level [README](../README.md) summarizes. It is the authoritative spec for
anyone integrating with or modifying the trust-critical paths.

## Identity

Every cached artifact is uniquely identified by a five-element tuple. All wire
types in `stow_types::api` carry these as **structured newtypes** (no raw
strings), so the rules below are enforced by `serde::Deserialize` at the API
boundary rather than by ad-hoc validators in each handler.

| Component | Newtype | Defined in | Allowed shape |
|---|---|---|---|
| Crate name | `CrateName` | `types/src/identity.rs` | ASCII alnum + `-`, `_`; 1–128 chars |
| Crate version | `CrateVersion` | `types/src/identity.rs` | strict `semver::Version` |
| Features | `FeaturesJson` | `types/src/identity.rs` | strictly sorted, deduplicated; serialized as JSON-encoded string for D1 column compatibility |
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

## D1 schema

### `artifacts`

The edge worker upserts rows here from the trusted CI register endpoint
(`edge/src/db.rs::insert_artifact_record`). The SQL template lives at
`edge/src/sql/insert_artifact.sql`; adding a column requires editing that
file plus the matching `bind` calls in `insert_artifact_record`. Column list
(in INSERT order):

`compile_key`, `c_metadata`, `extra_filename`, `target`, `rustc_version`,
`crate_name`, `version`, `features_json`, `dependency_c_metadata_json`,
`dependency_count`, `oci_reference`, `oci_digest`, `has_native`,
`artifact_kind`, `crate_types_json`, `profile_json`, `emit_json`,
`artifact_size`, `bundle_digest`, `bundle_size`, `compile_millis`,
`created_at`.

`compile_millis` is the wall-clock milliseconds the CI capture wrapper
measured for the rustc invocation that produced the artifact; the usage
statistics sum it to estimate CPU time the cache saved.

The composite uniqueness key is `(c_metadata, target, rustc_version)`.

### `dependency_graph_misses`

Every observed miss — exact, semantic, or graph — is logged as one data
point in the `stow_cache_misses` Analytics Engine dataset (binding
`STOW_ANALYTICS`), never as a D1 row: anonymous traffic cannot spend
billed row writes. A point's blobs are `(event, crate_name, version,
features_json, target, rustc_version, kind, path)` with `event = "miss"`
and `path` one of `exact`/`semantic`/`graph`, its doubles are `[1]`, and
the crate name is the index. A point carries artifact identity only — no
IP, no request id, no dependency graph, no lockfile hash.

A D1 row exists only for a miss whose admission was redeemed: when
`POST /api/v1/enqueue` verifies the challenge and proof-of-work it
inserts-or-updates the row with `admitted_at = now`, then forwards the
request to the scheduler and stamps `queued_at`. Each subsequent
graph-analysis request drains a batch of admitted rows whose
`queued_at IS NULL`, re-sends them to the scheduler as a retry channel
for failed sends (restoring the marker if the send fails again). Rows
queued more than 7 days ago are pruned opportunistically, as are
never-admitted rows older than 30 days (left over from when analysis
persisted every miss). Composite uniqueness key:
`(crate_name, version, features_json, target, rustc_version)`.

Enqueue admissions are stateless — the edge keeps no per-request record.
A miss response mints an `EnqueueAdmission` carrying the canonical
`EnqueueRequest`, an HMAC-SHA256 challenge over
`task_id ‖ canonical request JSON ‖ issue_minute`
(`STOW_POW_CHALLENGE_SECRET`), and a proof-of-work difficulty scaled by
scheduler queue depth (`STOW_POW_DEPTH_PER_BIT`, floored at
`STOW_POW_MIN_BITS` — an enqueue is never free — and capped at 24 bits).
The client solves `blake3(task_id ‖ challenge ‖ nonce)` and posts an
`EnqueueTicket` — the same request plus its nonce — to
`POST /api/v1/enqueue`, which recomputes the challenge over the carried
request (accepted during its issue minute and the minute after), checks
the proof-of-work, upserts the miss's `dependency_graph_misses` row as
admitted, and forwards the request to the scheduler. An unauthenticated
miss therefore leaves no D1 or scheduler trace at all — only the
Analytics Engine point — and a forged or tampered request cannot verify.

The miss lane is also depth-capped: once the scheduler reports
`pending >= STOW_MAX_QUEUE_PENDING` the handler refuses tickets with 429
and `Retry-After: 600`, and the Durable Object repeats the check inside
`enqueue` so a race of concurrent redemptions cannot overshoot by more
than one submit batch. Human-lane and RepoWriter-trusted submits
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

Accepted work lands in the scheduler's `human` lane, which dispatches
ahead of the `miss` lane: `claim_dispatchable_tasks` orders by lane
first, then Windows-family targets, then `first_requested_at` within a
lane, so no miss queueing
ahead of time can starve a human request, and human rows are exempt
from `STOW_DISPATCH_MIN_AGE_MINUTES` (the coalescing hold exists to
batch identical misses; a human already said exactly what they want).
Re-requesting a queued crate through this API promotes its row to the
human lane; the miss path never demotes a human row — the `lane` column
only ever moves `'miss' → 'human'`.

Two hard caps bound what one Turnstile token can spend:
`STOW_HUMAN_MAX_CLOSURE` refuses a request whose dependency closure
exceeds it (per target) with 422, and `STOW_HUMAN_DAILY_TASK_BUDGET`
limits human-lane tasks enqueued per UTC day — the scheduler Durable
Object keeps the counter (`human_daily_task_budget`, one row per UTC
date, charged atomically in `enqueue`) and refuses an overspending
submit with 429; the edge answers `Retry-After` in seconds until 00:00
UTC.

Dispatch is additionally capped per GitHub Actions runner family —
`stow_types::api::runner_family` maps each `CI_TARGET_TRIPLES` member
onto the pool its `runs-on` entry in `build-crate.yml` resolves to
(Linux, macOS, or Windows). `STOW_MAX_CONCURRENT_JOBS` bounds total
in-flight builds against the org's 60-runner fleet, and
`STOW_MAX_CONCURRENT_MACOS_JOBS` bounds macOS-targeted builds so a
full wave cannot occupy the whole 20-runner macOS pool. Within a lane,
Windows-family rows claim first regardless of request age because the
Windows legs are the slowest in a wave; rows whose family is saturated
stay pending, and the alarm then wakes at the earliest in-flight lease
expiry rather than re-firing immediately.

The handler resolves the requested version (newest non-prerelease,
non-yanked release when the body omits it), expands the crate's
dependency closure over crates.io metadata — normal and build edges,
optional-dependency feature activation, `cfg(...)` target restrictions —
and submits every uncovered node as an `EnqueueSource::HumanRequest`
task for each of `stow_types::api::CI_TARGET_TRIPLES`. `rustc_version`
is the current stable channel release, parsed from
`channel-rust-stable.toml` and cached in the Durable Object's
`rust_stable_channel` table for 60 minutes. `GET
/api/v1/requests/{task_id}` returns the task's `RequestStatus` — lane,
queue status, and its 1-based `human_lane_position` while it is still
pending in the human lane.

### Task dominance and claim-time coverage

A trusted build publishes every library crate in its task's closure, so
enqueueing one task per uncovered closure node would build the same
crates many times over. Both admission paths (`build_enqueue_requests`)
instead compute the transitive closure of every node in the exact graph
and, for each uncovered node that lies inside another uncovered node's
closure, record its *immediate dominator* — the uncovered node with the
smallest closure that contains it. A task's only `depends_on` edge points
at its immediate dominator, so the roots of a wave dispatch first while
the dominated tasks wait; covered intermediates are looked through, and
a node no other uncovered node reaches is a root.

When a dominator's publish lands, the dominated tasks are already
served. `claim_dispatchable_tasks` asks the artifact catalog (D1
`artifacts`, servable rows only) which of the candidate rows' exact
`(crate, version, features_json, target, rustc_version)` identities
exist and retires those rows as `completed` without a build. Only plain
crates.io tasks are asked about — a project-source task shares nothing
with the catalog's keys, and a lockfile-preserving overlay build is a
different artifact. If a dominator fails, its dominated tasks unblock
(failed dependencies never block) and build individually — the old
leaf-first behaviour is the failure path, not the default.

### Migrations

The D1 schema lives in `edge/migrations/NNNN_*.sql` — every file is written
idempotent (`IF NOT EXISTS`), so `deploy-edge.yml` re-executes the whole
directory against `stow-prod` before each deploy with no bookkeeping table.
The Worker assumes the schema exists; `wrangler d1 execute --file` applies
the same files to mock/local databases (see `scripts/mock-e2e.sh`).

## OCI bundle layout

Every artifact is a tag of the single GHCR package
`ghcr.io/water-rs/stow-cache`, referenced as
`ghcr.io/water-rs/stow-cache:{crate}.{version}-{target_short}-{rustc_short}-{feat_hash}-{c_metadata}{kind_suffix}`
(see `types/src/registry.rs`). The crate name is the tag's first
`.`-separated segment — crates.io names never contain `.`, so the split is
unambiguous (`sha-1.0.10.0-…` is crate `sha-1`, version `0.10.0`). One
package means one GHCR visibility flip covers the whole cache: GHCR
creates packages private and has no API to change that.

Each artifact is two OCI images on that package. The signed image is the
tag above: its config is the `ArtifactBlobConfig` and it carries one
zstd-compressed layer per output file plus, when the build script produced
one, the native `OUT_DIR` archive; cosign signs this image. Next to it the
trusted publish stage pushes `<tag>.bundle`, a single-layer image whose
layer is the bundle tar a CLI consumes (`stow_types::bundle::assemble_bundle`).
The bundle needs no signature of its own: it embeds the signed manifest and
config, the signature materials, and the layers byte-for-byte, and the CLI
verifies that material after download. The record registered with the
edge carries the bundle layer's digest and size (`bundle_digest`,
`bundle_size`); the edge streams that blob by digest and never assembles,
buffers or inspects it — the publish stage validated the tar
(`stow_types::bundle_schema`) before pushing it.

| Path | Content |
|---|---|
| `manifest.json` | `ArtifactBundleManifest` (oci_reference, oci_digest, embedded `ArtifactBlobConfig`, sigstore signatures) |
| `oci/manifest.json` | OCI image manifest of the signed image (registry bytes verbatim) |
| `oci/config.json` | OCI image config of the signed image (registry bytes verbatim) |
| `sigstore/payload-<n>.json` | Cosign simple-signing payloads, one per signature layer |
| `files/<name>` | One entry per layer in manifest order: `lib<crate>-<extra>.rlib`, `.rmeta`, `.so`/`.dylib`/`.dll`, the native archive |

Batch responses use `bundles/<c_metadata>.tar` paths inside an outer tar that
also contains a `batch-manifest.json` (`ArtifactBatchManifest`).

Rows registered before bundles were published carry an empty
`bundle_digest`; every serving lookup treats such a row as a miss (it is
neither streamed nor pruned). `stow-build backfill-bundles` lists them through
`GET /api/v1/admin/artifacts/unbundled`, republishes each bundle from the
signed image already in GHCR, and re-registers the record.

Constants (media types, paths) are defined in `types/src/bundle.rs`.

## Artifact index

Every servable artifact row is additionally published as a signed,
per-slice index so a client resolves cache coverage locally instead of
querying the edge (#188). One index exists per `(target, rustc_version)`
pair: the tag `index.<target>.<rustc>` on `ghcr.io/water-rs/stow-cache`
(`stow_types::index::index_tag`) names a single-layer OCI artifact whose
layer is the zstd-compressed JSON `ArtifactIndex` (media type
`application/vnd.stow.index.v1+zstd`; config
`application/vnd.stow.index.config.v1+json`). The typed header
(`types/src/index.rs`) pins `format_version` — a decoder rejects a
foreign version — and a `row_count` checked against the decoded body.

`.github/workflows/index-publish.yml` is dispatch-only: scheduled
workflows run on the default branch (`dev`), whose identity the CLI
rejects, so `index-publish-cron.yml` ticks every ten minutes and
dispatches it on `main`, and its first step refuses any other ref. A run
resolves the current stable rustc from the
channel manifest, exports each `CI_TARGET_TRIPLES` slice through
`GET /api/v1/admin/index/{target}/{rustc_version}` (keyset-paginated by
`c_metadata`, `SchedulerCaller`-gated) via `stow-admin index export`, and
pushes it with `oras`. Because the header's `generated_at` makes every
export byte-unique, the run does not compare blob digests: the export
reports a `content_sha256` over everything but the timestamp, the
manifest carries it as the `dev.stow.index.content-sha256` annotation,
and an equal annotation skips push and signature — an unchanged slice
never churns the tag. Pushed indexes are cosign-signed keyless under
`index-publish.yml@refs/heads/main`
(`stow_types::trusted_builder::INDEX_CERTIFICATE_IDENTITY`), the same
Fulcio chain the CLI verifies for artifact bundles.

## Trust boundaries

```
              GitHub Actions: build-crate.yml @ refs/heads/main  ← root of trust
   ┌──────────────────────────────┐        ┌──────────────────────────────┐
   │ build job (untrusted)        │ upload │ publish job (trusted)        │
   │ contents: read, no secrets   │──────► │ packages: write, id-token    │
   │ stow-build build             │ artifact│ stow-build publish           │
   │ runs third-party build.rs    │        │ validates, pushes, signs,    │
   └──────────────────────────────┘        │ registers, reports           │
                                           └─┬────────────────────────────┘
                                             │ POST /api/v1/admin/artifacts/register
                                             │ (Bearer: github-oidc)
                                             ▼
  client (cli)  ──── zenwave ──►  edge worker (skyzen) ──► CF D1 (authoritative)
        ▲                              │ CfFetch
        │ inject                       ▼
   cargo target/                  GHCR (OCI)
```

What each hop is allowed to do:

| Hop | Reads | Writes |
|---|---|---|
| stow CLI (`cli/`) | edge HTTP responses: bundle blobs streamed from GHCR | local cache only |
| edge worker (`edge/`) | crates.io, D1, GHCR, Analytics Engine SQL API | D1 `artifacts` rows (only via `/api/v1/admin/artifacts/register`, gated by the `build-crate.yml` OIDC pin / repo push users, and bound to the dispatched task's dependency closure — an OIDC write must name an in-flight task and every record's `(crate, version)` must be the task crate or a closure member); scheduler queue; `dependency_graph_misses` (admitted misses only); `stow_cache_misses` Analytics Engine points (every miss); `stow_events` Analytics Engine points (sampled hits, opt-in shares) |
| scheduler DO | D1 queue tables | D1 queue tables; GitHub `workflow_dispatch` of `build-crate.yml` on `main` |
| `stow-build build` (untrusted job) | crates.io tarball, the task | its own output directory (task, plan, content-addressed blobs) |
| `stow-build publish` (trusted job) | the build output, crates.io (closure resolution), GHCR token, OIDC (`id-token: write` — cosign plus the edge's trusted endpoints) | GHCR objects; sigstore signatures; admin/register POSTs; scheduler `/complete` |
| `report-failure` job (`build-crate.yml`) | the dispatch task input; OIDC (`id-token: write`) | scheduler `/complete` failure reports |
| `index-publish.yml` (dispatched on `main` by `index-publish-cron.yml`) | D1 `artifacts` via the edge admin index endpoint; GHCR manifests; OIDC (`id-token: write`) | `index.*` tags and their sigstore signatures on `ghcr.io/water-rs/stow-cache` |

The build and publish jobs never share a process or an environment. The build job's
`GITHUB_TOKEN` is `contents: read` and it has no `id-token` grant, so a
malicious `build.rs` or proc-macro can neither push to GHCR nor mint an OIDC
token that Fulcio would sign for. Everything it hands over is
attacker-influenced, so the publisher (`ci/src/stage.rs`, `ci/src/closure.rs`,
`ci/src/validate.rs`) establishes what it believes on its own:

- the task comes from the `workflow_dispatch` input, not from the build job;
  the build output's copy must equal it;
- every blob is content-addressed and re-hashed against the digest the plan
  records for it;
- every planned artifact's `target` and `rustc_version` equal the task's;
- every planned artifact's `(crate, version)` is in the dependency closure the
  publisher resolves itself from a fresh crates.io download with
  `cargo metadata` (which never executes crate code): the crates reachable
  from the task crate over normal and build edges on the task's platform.
  Dev-dependencies and other platforms' dependencies are never compiled by
  the pipeline, so a plan entry for one of them is a fabrication and is
  rejected;
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

CI no longer holds a Cloudflare D1 credential. The edge worker owns the only
write path to `artifacts` and authorizes it via GitHub identity on the
`Authorization: Bearer` header — the `build-crate.yml` Actions OIDC token in
CI (signature verified against GitHub's JWKS, with `iss`/`aud`/`repository`/
`job_workflow_ref`/`exp` pinned), or any credential GitHub would accept a
push from on the repo (probed via the `git-receive-pack` ref
advertisement — uniform across user tokens, fine-grained PATs, and
installation tokens). The CLI verifies cosign signatures on every cache hit
(`cli/src/verify.rs`) before injecting bytes into Cargo's target directory,
so a polluted record (e.g. from a stolen credential) produces a 404 +
stale-row prune on the client, not malicious code.

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

> **Register binding.** The endpoint is authenticated by GitHub identity,
> and an OIDC write must additionally name the scheduler task the run was
> dispatched for (`RegisterArtifactsRequest.task_id`). The edge requires
> the task to be in flight and every record to carry the task's target and
> rustc version, and it expands the task's crates.io dependency closure
> with the same resolver `POST /api/v1/requests` uses: a record for a
> `(crate, version)` outside that closure rejects the whole request before
> any row is written. A compromised publish job for crate X can therefore
> only register rows crate X's own build could produce. Tasks that resolve
> a lockfile the edge cannot reproduce (`project_source` checkouts and
> `preserve_lockfile` overlays) skip the crates.io expansion — their
> binding narrows to the task's target/rustc identity — and push-user
> callers may omit `task_id` for the operator backfill path.
>
> **Future direction.** Requiring the request body itself to be
> cosign-signed by the same identity that signs OCI bundles would make
> register signature-rooted end to end.

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
output present. Outputs are reflink-or-copied into a sibling temp dir,
SHA-256 hashed from the staged bytes, then atomically renamed into the
entry dir under the fs2 exclusive entry lock. For `links=` crates the same
pass captures the build script's `OUT_DIR` (the `stow-types` capture shared
with CI — `cargo:` directives minus `rerun-if-*`/`warning=`, every
`OUT_DIR` file with its sha256, `.a`/`.lib` static libs) into `native/out/`
so the remote and local restore paths are identical.

### Eviction

Local entries join the remote LRU: post-insert `evict_entries` runs against
`artifact_cache_max_bytes`, `last_accessed_ms` bumps on every hit, and
`size_bytes` charges native `OUT_DIR` bytes too. Eviction is
provenance-agnostic.

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

- `preheat.yml` (manual) analyzes every non-archived, non-fork water-rs
  repository with `stow predict` on each CI target; misses surface
  through the ordinary admission path.
- `preheat-admin.yml` (manual, Actions-OIDC authenticated) seeds the
  shared base pool directly against the scheduler: `preheat top` for
  the top-N library crates, `preheat binary-overlay` for the top-N
  binaries (resolved `--locked`), an optional `project` repository
  seeded as a project-source task per target, and the checked-in
  `preheat/projects.toml` showcase list via the `projects_file` input —
  `stow-admin preheat projects` submits one project-source task per
  `[[project]]` entry per target, resolving each repo's `ref_policy` to
  an immutable commit with `git ls-remote` (`latest-tag` picks the
  newest semver tag, `default-branch` the remote `HEAD`).
- `release-reheat.yml` (every two hours plus manual) polls
  `channel-rust-stable.toml`; on a version it has not seen it dispatches
  `preheat-admin.yml` (`project=waterui`, the projects file, the binary
  overlay) and `preheat.yml`. An `actions/cache` entry keyed
  `release-reheat-<version>` is the already-re-heated marker, so the
  poll is idempotent and a failed dispatch simply retries on the next
  tick.
- `preheat-missed.yml` (weekly, Mondays 06:00 UTC, plus manual) promotes
  observed demand: `stow-admin preheat missed` queries the
  `stow_cache_misses` Analytics Engine dataset for the top-K
  `(crate, version, features)` tuples per target by sampled miss volume
  over the trailing week — `semantic` and `graph` misses only, the kinds
  that carry a concrete crates.io version — and submits them to the
  scheduler in one batch through the same authenticated endpoint the
  other admin lanes use, with the miss count as the task's `downloads`
  priority signal.

## Usage statistics

Anonymous usage events go to the `stow_events` Analytics Engine dataset
(binding `STOW_STATS`), never to D1 — exactly like misses, anonymous
traffic cannot spend billed row writes. Two event shapes exist; both are
gated on the `x-stow-no-analytics: 1` request header, which the CLI sends
on every request when `STOW_NO_ANALYTICS=1` is set (`edge/src/stats.rs`'s
`AnalyticsConsent` extractor — every write takes the consent as an
argument, so the opt-out is honoured by construction).

- `hit` — written by the three artifact-serving paths (exact GET,
  semantic POST, batch POST) with probability 1/10; the stored sample
  weight (`double1 = 10`) scales counts back up at query time. Blobs are
  `(event, target, rustc_version, crate_name, version, size_bucket,
  cli_version, os_family, surface)`; doubles are `(sample_weight,
  compile_millis, bundle_size)`. The point's sole index is a
  daily-salted install hash —
  `hex(HMAC-SHA256(HMAC-SHA256(STOW_STATS_SALT_SECRET, YYYY-MM-DD), ip))[..16]` —
  which counts distinct installs per day and cannot be joined across
  days; the client IP is hashed inside the worker and never written.

`GET /api/v1/stats` answers `UsageStats` by running the
`edge/src/sql/stats_*.sql` queries against the Analytics Engine SQL API
(`POST …/accounts/{CF_ACCOUNT_ID}/analytics_engine/sql`, authorized by
the `CF_ANALYTICS_TOKEN` secret) and caches the response in the Cache
API for one hour per colo. `daily_active_installs_7d` averages the
per-day distinct install hashes over 7 days (the daily salt makes a
weekly unique count impossible by design) and is suppressed below 20 —
stow publishes no small counts. `GET /stats`
renders the same numbers as a public page. The full data contract —
fields, retention, sampling, opt-out — is documented in
[`PRIVACY.md`](../PRIVACY.md).

## Wire-protocol surface (HTTP)

All endpoints live on the edge worker. `?` paths use `Json<T>` extractors,
which means the body is parsed *after* the per-handler extractor chain — and
the bearer-credential extractor (`SchedulerCaller` / `ArtifactWriteCaller`)
is declared first on authenticated handlers, so unauthorized POSTs
short-circuit before deserialization.

| Method + path | Auth | Body | Response | Purpose |
|---|---|---|---|---|
| GET `/` | none | — | HTML | Landing page: numbers from the acceleration audit, how it works, and the crate request form (askama template in `edge/templates/`, Turnstile site key from `TURNSTILE_SITE_KEY`) |
| GET `/stats` | none | — | HTML | Public usage-statistics page — the `GET /api/v1/stats` numbers rendered in the site's style |
| GET `/api/v1/stats` | none | — | `UsageStats` | Anonymous usage statistics from the Analytics Engine SQL API, Cache-API-cached for one hour |
| GET `/api/v1/artifacts/{target}/{rustc_version}/{c_metadata}?crate=<name>` | none | — | the `<tag>.bundle` blob, streamed | Exact-key fetch |
| HEAD `/api/v1/artifacts/{target}/{rustc_version}/{c_metadata}` | none | — | 200 / 404 + `content-length` (the bundle's size) | Existence probe |
| POST `/api/v1/artifacts/semantic` | none | `SemanticArtifactRequest` | the `<tag>.bundle` blob, streamed | Semver-relaxed lookup |
| POST `/api/v1/artifacts/batch` | none | `BatchArtifactRequest` | tar of bundles + manifest | Bulk fetch |
| POST `/api/v1/admin/artifacts/register` | Bearer: `build-crate.yml` OIDC or repo push user | `RegisterArtifactsRequest` | `OkResponse` | Trusted CI registers built artifacts; the OIDC caller's `task_id` binds the write to the dispatched task's target/rustc and dependency closure |
| GET `/api/v1/admin/artifacts/unbundled?limit=N` | Bearer: `build-crate.yml` OIDC or repo push user | — | `Vec<ArtifactRecord>` | Rows without a published bundle, for `stow-build backfill-bundles` |
| GET `/api/v1/admin/panic` | Bearer: repo-workflow OIDC or push user | — | `PanicSwitch` | Read the anonymous-traffic circuit breaker |
| POST `/api/v1/admin/panic` | Bearer: repo-workflow OIDC or push user | `PanicSwitch` | `PanicSwitch` | Flip the circuit breaker — anonymous routes shed with 503 + `Retry-After` |
| GET `/api/v1/admin/index/{target}/{rustc_version}?after=<c_metadata>&limit=N` | Bearer: repo-workflow OIDC or push user | — | `ArtifactIndexPage` | Keyset page of the slice's servable rows, for `stow-admin index export` |
| GET `/api/v1/admin/status` | Bearer: repo-workflow OIDC or push user | — | `AdminStatus` | Operator view: lane depths, oldest pending age, in-flight rows with GitHub run ids, per-target 24 h outcomes, panic flag — `stow-admin status` |
| GET `/api/v1/admin/queue?task_ids=…&status=&target=&crate=&older_than=&limit=` | Bearer: repo-workflow OIDC or push user | — | `Vec<QueueTask>` | Selector-filtered queue rows (≤500), newest transition first — `queue list` and the mutation preview |
| POST `/api/v1/admin/queue/{retry\|cancel\|promote\|purge}` | Bearer: repo-workflow OIDC or push user | `QueueSelector` | `QueueMutationResult` | Queue transitions; the verb's domain predicates conjoin with the selector — `queue retry\|cancel\|promote\|purge` |
| GET `/api/v1/admin/coverage/{crate_name}?version=&target=` | Bearer: repo-workflow OIDC or push user | — | `CrateCoverage` | Per-CI-target servable identities for one crate — `coverage` |
| GET `/api/v1/admin/artifacts?rustc_version=&target=&crate=&limit=` | Bearer: repo-workflow OIDC or push user | — | `Vec<ArtifactRecord>` | Bounded catalog listing (≤1000) — the prune preview |
| GET `/api/v1/admin/artifacts/{target}/{rustc_version}/{c_metadata}` | Bearer: repo-workflow OIDC or push user | — | `ArtifactInspection` | Catalog row plus the bundle's OCI manifest from GHCR — `artifacts inspect` |
| POST `/api/v1/admin/artifacts/prune` | Bearer: repo-workflow OIDC or push user | `ArtifactPruneRequest` | `ArtifactPruneResponse` | Delete a retired toolchain's catalog rows and invalidate their lookup cache entries; GHCR tags are not deleted — `artifacts prune` |
| POST `/api/v1/admin/preheat/plan` | Bearer: repo-workflow OIDC or push user | `PreheatPlanRequest` | `PreheatPlanResponse` | Dry-run closure expansion + dominance pruning for a crate request — `preheat plan` |
| POST `/api/v1/catalog/graph` | none | `DependencyGraphRequest` | `DependencyGraphResponse` | Coverage analysis + miss admissions |
| POST `/api/v1/enqueue` | HMAC challenge + proof-of-work | `EnqueueTicket` | `OkResponse` | Redeem a miss admission into a scheduler enqueue |
| POST `/api/v1/requests` | Cloudflare Turnstile token | `CrateRequest` | `CrateRequestOutcome` | Human request: enqueue a crate's closure on every CI target in the human lane |
| GET `/api/v1/requests/{task_id}` | none | — | `RequestStatus` | Task status + human-lane position |
| POST `/api/v1/scheduler/tasks/submit` | Bearer: repo-workflow OIDC or push user | `Vec<EnqueueRequest>` | `SchedulerSubmitResponse` | Submit one task batch |
| POST `/api/v1/scheduler/complete` | Bearer: `build-crate.yml` OIDC or push user | `BuildCompleteReport` | `OkResponse` | CI reports completion |
| GET `/api/v1/scheduler/status` | none | — | `SchedulerStatus` | Queue introspection |

Authenticated POSTs resolve the `Authorization: Bearer` credential to a GitHub identity in the extractor, before the body is parsed.

Every `/api/v1/` path except `/api/v1/artifacts/` sits behind the zone
rate-limit rule documented in
[`DEPLOYMENT.md`](DEPLOYMENT.md#one-time-cloudflare-setup) — 60 requests
per 10 seconds per source IP over the API prefix, not per route. Artifact
reads are carved out because a warm build legitimately fetches its whole
closure in a burst; that path costs one Worker request per hit and is
bounded by the panic switch and billing notifications instead. The
trusted write endpoints (`admin/artifacts/register`,
`scheduler/tasks/submit`, `scheduler/complete`) are inside the limited
prefix, which is fine at CI's request rate: a build makes one register
call per task chunk.

When even that is too much — Cloudflare has no spend cap — the panic
switch sheds anonymous traffic outright. `POST /api/v1/admin/panic`
(`stow-admin panic on`) writes a flag into the scheduler Durable Object's
`settings` table, and a middleware on the anonymous route group answers
every such request `503 Service Unavailable` with `Retry-After: 300`
before its handler runs. The flag is read through the Cache API under a
fixed key (`s-maxage=60`), so a per-request read costs one local cache
probe and a flip propagates within 60 s — immediately in the colo
that wrote it, whose cache entry is deleted. The trusted
`/api/v1/admin/*` and `/api/v1/scheduler/*` routes are never gated, so CI
keeps registering and completing builds and the operator can always flip
the switch back off.

## Tunables (Cloudflare bindings)

The edge worker reads runtime knobs from `vars` bindings via
`runtime_settings::ResolverSettings::from_env`. Defaults apply when a binding
is unset or malformed.

| Binding | Default | Purpose |
|---|---|---|
| `STOW_BATCH_FETCH_CONCURRENCY` | 32 | Concurrent OCI bundle fetches per batch request; also caps concurrent crates.io fetches while resolving a graph's cold direct entries |
| `STOW_MAX_EXPANDED_TASKS` | 4096 | Cap on the size of an expanded transitive graph |
| `STOW_DB` (D1 binding) | required | Artifact catalog database |
| `SCHEDULER` (Durable Object binding) | required | Build scheduler |
| `GITHUB_REPO` | `water-rs/stow` | Repo every trusted credential must resolve inside (OIDC `repository` claim / push-permission check) |
| `STOW_OIDC_AUDIENCE` | `https://stow.waterui.dev` | `aud` the edge pins on Actions OIDC tokens; must equal the repo variable CI requests |
| `STOW_POW_CHALLENGE_SECRET` | required (secret) | HMAC key minting and verifying enqueue-admission challenges |
| `STOW_POW_DEPTH_PER_BIT` | `50` | Pending scheduler tasks per extra proof-of-work bit; `0` disables the depth scaling (the `STOW_POW_MIN_BITS` floor still applies) |
| `STOW_POW_MIN_BITS` | `12` | Floor on enqueue proof-of-work difficulty — an enqueue is never free, even on an empty queue |
| `STOW_MAX_QUEUE_PENDING` | `2000` | Pending depth at which miss-lane enqueues are refused (429 + `Retry-After: 600`); checked in the edge handler and in the scheduler object. Human-lane and trusted submits are exempt |
| `STOW_HUMAN_MAX_CLOSURE` | `150` | Largest dependency closure `POST /api/v1/requests` accepts per target; larger closures get 422 |
| `STOW_HUMAN_DAILY_TASK_BUDGET` | `2000` | Human-lane tasks accepted per UTC day, counted in the scheduler object's `human_daily_task_budget` table; overspending submits get 429 + `Retry-After` to 00:00 UTC |
| `TURNSTILE_SITE_KEY` | `0x4AAAAAAE8LjhnMsqdVhiSp` | Public site key of the request page's invisible Turnstile widget |
| `TURNSTILE_SECRET_KEY` | required (secret) | Turnstile secret `POST /api/v1/requests` verifies tokens against |
| `GHCR_BASE_URL` | `https://ghcr.io/v2/water-rs/stow-cache` | Override for mock-registry runs |

## Local development

* `cd edge && cargo check` builds the edge worker against `wasm32-unknown-unknown`
  (the `edge/.cargo/config.toml` sets the default target so the workspace
  default `cargo check -q` continues to ignore edge).
* `STOW_TRACE_FILE=/tmp/stow-cold.json stow check ...` writes a Chrome-format
  trace covering every instrumented `stow.*` span; open in chrome://tracing or
  Perfetto.
* `STOW_BUILD_LOCAL_CI_LISTEN=127.0.0.1:7000` activates the dev-only `axum`
  dispatch endpoint inside `ci/src/local_server.rs`. It is gated; production
  CI does not start it.
* `stow-mock-registry` provides an OCI v2 + cosign-compatible local registry.
