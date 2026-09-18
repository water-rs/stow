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
|| crate_types_json || emit_json)` — see `types/src/upload_plan.rs::compute_compile_key`.

## D1 schema

### `artifacts`

The edge worker upserts rows here from the trusted CI register endpoint
(`edge/src/db.rs::insert_artifact_record`). The SQL template lives at
`edge/src/sql/insert_artifact.sql`; adding a column requires editing that
file plus the matching `bind` calls in `insert_artifact_record`. Column list
(in INSERT order):

`compile_key`, `c_metadata`, `extra_filename`, `target`, `rustc_version`,
`crate_name`, `version`, `features_json`, `dependency_c_metadata_json`,
`oci_reference`, `oci_digest`, `has_native`, `artifact_kind`,
`crate_types_json`, `profile_json`, `emit_json`, `artifact_size`, `created_at`.

The composite uniqueness key is `(c_metadata, target, rustc_version)`.

### `dependency_graph_misses`

The edge writes one row per cache miss observed during graph analysis.
Each subsequent graph-analysis request drains a batch of rows whose
`queued_at IS NULL`, enqueues the corresponding builds alongside its own
misses, and marks them queued (restoring the marker if the scheduler send
fails). Rows queued more than 7 days ago are pruned opportunistically.
Composite uniqueness key:
`(crate_name, version, features_json, target, rustc_version)`.

### Migrations

Incremental `ALTER TABLE` statements live in
`shim/src/schema.rs::REQUIRED_ARTIFACT_COLUMNS`. The edge
worker calls `db::ensure_schema` at request time; CI does not migrate.

## OCI bundle layout

Each artifact is an OCI image with a single zstd-compressed tar layer. The tar
contents follow `stow_types::bundle`:

| Path | Content |
|---|---|
| `manifest.json` | `ArtifactBundleManifest` (oci_reference, oci_digest, embedded `ArtifactBlobConfig`, sigstore signatures) |
| `oci/manifest.json` | OCI image manifest (passthrough from registry) |
| `oci/config.json` | OCI image config (passthrough) |
| `sigstore/<n>.payload` | Cosign signature payloads, one per signer |
| Per-output files | `lib<crate>-<extra>.rlib`, `.rmeta`, `.so`/`.dylib`/`.dll`, native libs |

Batch responses use `bundles/<c_metadata>.tar` paths inside an outer tar that
also contains a `batch-manifest.json` (`ArtifactBatchManifest`).

Constants (media types, paths) are defined in `types/src/bundle.rs`.

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
                                             │ (x-stow-register-token)
                                             ▼
  client (cli)  ──── zenwave ──►  edge worker (skyzen) ──► CF D1 (authoritative)
        ▲                              │ CfFetch
        │ inject                       ▼
   cargo target/                  GHCR (OCI)
```

What each hop is allowed to do:

| Hop | Reads | Writes |
|---|---|---|
| stow CLI (`cli/`) | edge HTTP responses; signed OCI bundles via 302 redirect | local cache only |
| edge worker (`edge/`) | crates.io, D1, GHCR | D1 `artifacts` rows (only via `/api/v1/admin/artifacts/register`, gated by `REGISTER_AUTH_TOKEN`); scheduler queue; `dependency_graph_misses` (informational) |
| scheduler DO | D1 queue tables | D1 queue tables; GitHub `workflow_dispatch` of `build-crate.yml` on `main` |
| `stow-build build` (untrusted job) | crates.io tarball, the task | its own output directory (task, plan, content-addressed blobs) |
| `stow-build publish` (trusted job) | the build output, crates.io (closure resolution), GHCR token, OIDC, `STOW_REGISTER_AUTH_TOKEN`, `SCHEDULER_AUTH_TOKEN` | GHCR objects; sigstore signatures; admin/register POSTs; scheduler `/complete` |

The two jobs never share a process or an environment. The build job's
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
in there cannot read the runner's environment or credentials, the stow
checkout, or rewrite another crate's registry source.

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
write path to `artifacts` and authorizes it via a constant-time token compare
on the `x-stow-register-token` header. The CLI verifies cosign signatures on
every cache hit (`cli/src/verify.rs`) before injecting bytes into Cargo's
target directory, so a polluted record (e.g. from a stolen register token)
produces a 404 + stale-row prune on the client, not malicious code.

> **Future direction.** The register endpoint is currently shared-secret
> authenticated. The next iteration will require the request body to be
> cosign-signed by the same identity that signs OCI bundles, removing the
> shared-secret surface and making register itself signature-rooted.

## Wire-protocol surface (HTTP)

All endpoints live on the edge worker. `?` paths use `Json<T>` extractors,
which means the body is parsed *after* the per-handler extractor chain — and
the auth token extractor (`SchedulerAuthToken`) is declared first on
authenticated handlers, so unauthorized POSTs short-circuit before
deserialization.

| Method + path | Auth | Body | Response | Purpose |
|---|---|---|---|---|
| GET `/api/v1/artifacts/{target}/{rustc_version}/{c_metadata}?crate=<name>` | none | — | OCI bundle bytes (or 302 redirect to GHCR) | Exact-key fetch |
| HEAD `/api/v1/artifacts/{target}/{rustc_version}/{c_metadata}` | none | — | 200 / 404 + `content-length` | Existence probe |
| POST `/api/v1/artifacts/semantic` | none | `SemanticArtifactRequest` | OCI bundle bytes | Semver-relaxed lookup |
| POST `/api/v1/artifacts/batch` | none | `BatchArtifactRequest` | tar of bundles + manifest | Bulk fetch |
| POST `/api/v1/admin/artifacts/register` | `x-stow-register-token` (constant-time) | `Vec<ArtifactRecord>` | `OkResponse` | Trusted CI registers built artifacts |
| POST `/api/v1/catalog/graph` | none | `DependencyGraphRequest` | `DependencyGraphResponse` | Coverage analysis + miss recording |
| POST `/api/v1/scheduler/tasks/submit` | `x-stow-scheduler-token` (constant-time) | `Vec<EnqueueRequest>` | `OkResponse` | Submit builds |
| POST `/api/v1/scheduler/complete` | `x-stow-scheduler-token` | `BuildCompleteReport` | `OkResponse` | CI reports completion |
| GET `/api/v1/scheduler/status` | none | — | `SchedulerStatus` | Queue introspection |

Authenticated POSTs use `subtle::ConstantTimeEq` for the token compare.

## Tunables (Cloudflare bindings)

The edge worker reads runtime knobs from `vars` bindings via
`runtime_settings::ResolverSettings::from_env`. Defaults apply when a binding
is unset or malformed.

| Binding | Default | Purpose |
|---|---|---|
| `STOW_RESOLVER_CONCURRENCY` | 32 | Concurrent crates.io graph fetches |
| `STOW_BATCH_FETCH_CONCURRENCY` | 32 | Concurrent OCI bundle fetches per batch request |
| `STOW_MAX_EXPANDED_TASKS` | 4096 | Cap on the size of an expanded transitive graph |
| `STOW_DB` (D1 binding) | required | Artifact catalog database |
| `SCHEDULER` (Durable Object binding) | required | Build scheduler |
| `SCHEDULER_AUTH_TOKEN` | optional | If set, scheduler endpoints require this token |
| `REGISTER_AUTH_TOKEN` | required for `/api/v1/admin/artifacts/register` | Shared secret authorizing CI's artifact-record writes |
| `GHCR_TOKEN` | required | Pull token for `ghcr.io/water-rs/stow-cache` |
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