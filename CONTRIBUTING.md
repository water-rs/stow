# Contributing to stow

## Workspace layout

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the trust model
and `AGENTS.md` for repo invariants. The TL;DR: `cli/` is the user
binary, `edge/` is a Cloudflare Worker compiled to wasm32, `ci/` is the
trusted GitHub-Actions builder, `admin/` is the operator CLI,
`mock-registry/` is a dev-only OCI server.

## Build expectations

- `cargo check -q` from the repo root must succeed for the host
  workspace. `edge/` is a default member, so this covers its
  host-compilable half too — the Cloudflare-bound modules are
  wasm32-gated and skip themselves.
- `cargo check` from `edge/` builds the wasm worker. The crate's
  `.cargo/config.toml` sets `target = "wasm32-unknown-unknown"` so
  plain `cargo` invocations from inside `edge/` pick up the right cfg.
  Do not delete that file.
- The edge worker bundle is repackaged by `skyzen dev` (or `skyzen
  deploy`). It calls `wasm-bindgen` against `target/wasm32-unknown-unknown/debug/stow_edge.wasm`,
  so the `wasm-bindgen` generator embedded in `skyzen-cli` MUST match
  `wasm-bindgen` in stow's `Cargo.lock` (skyzen-cli 0.4.2, the version
  CI installs, ships `=0.2.120`, same as the lockfile). When you bump
  `wasm-bindgen` in stow, install a skyzen-cli release that embeds the
  same version and update the release and archive digest pinned in
  `.github/actions/install-skyzen-cli/action.yml`.

## Style rules (enforced by review)

- Fast-fail: if an unexpected case occurs, return `Err` with a
  descriptive message; do not silently fall through.
- Use `tracing` not `println!`.
- No multi-line embedded string literals. Pull them into `templates/`
  or `sql/` and `include_str!`.
- Identity tuples (`CrateName`, `CrateVersion`, `FeaturesJson`,
  `TargetTriple`, `WireRustcVersion`, `CMetadata`,
  `DependencyCMetadataJson`) are wire-validated by `serde::Deserialize`
  at the API boundary. Don't reinvent them with raw strings.
- The scheduler has one schema — `edge/src/scheduler/schema.sql`. New
  queue columns go in that file, `TaskRow`, the SELECT column list in
  `claim_dispatchable_tasks`, and the INSERT in `enqueue`.
- Scheduler schema changes are operations work, never request work: no
  request handler, and not the alarm, may issue DDL (CREATE / ALTER /
  DROP), a backfill, or a schema check — request code assumes the schema
  exists and lets its own SQL fail loudly when it does not. The only
  code that issues DDL is `queue.rs::reset`, behind
  `POST /api/v1/admin/scheduler/reset` (`stow-admin scheduler reset
  --yes` manually), which drops every object and re-executes
  `schema.sql`; the queue and recorded slices are destroyed and refill
  from the lanes that feed them. A fresh deployment's operator runs it
  once to create the store.

## Testing changes locally

End-to-end mock setup is documented in
[`docs/MOCK.md`](docs/MOCK.md). For unit tests:

```sh
cargo nextest run --workspace                     # every member, stow-edge's host-compilable tests included — what CI runs
cargo test --doc --workspace
```

`--workspace` covers `stow-edge` on the host target automatically: its
`.cargo/config.toml` wasm32 pin only applies to invocations from inside
`edge/` itself, so from the repo root the crate builds for the host and
its non-wasm-gated tests run — matching the CI matrix's three OSes.

The `lint` job in `test.yml` enforces all three of these on stable —
run them before pushing:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p stow-edge --target wasm32-unknown-unknown -- -D warnings
```

## Schema-evolving changes

Any change that alters wire types in `types/src/api.rs` changes the
worker bundle. `skyzen dev`/`skyzen build`/`skyzen deploy` regenerate
it under `edge/.skyzen/` on every invocation, so no manual repackaging
step is needed — deploys from `deploy-edge.yml` always build fresh.

## Commit hygiene

Follow the existing repo style: short imperative subject; body
explains the *why* not the *what*. Don't lump trust-model changes with
unrelated fixes.