# Contributing to stow

## Workspace layout

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the trust model
and `CLAUDE.md` for repo invariants. The TL;DR: `cli/` is the user
binary, `edge/` is a Cloudflare Worker compiled to wasm32, `ci/` is the
trusted GitHub-Actions builder, `admin/` is the operator CLI,
`mock-registry/` is a dev-only OCI server.

## Build expectations

- `cargo check -q` from the repo root must succeed for the host
  workspace. The `edge/` crate is excluded from the default workspace
  members so it doesn't drag a wasm32 build into every host check.
- `cargo check` from `edge/` builds the wasm worker. The crate's
  `.cargo/config.toml` sets `target = "wasm32-unknown-unknown"` so
  plain `cargo` invocations from inside `edge/` pick up the right cfg.
  Do not delete that file.
- The edge worker bundle is repackaged by `skyzen dev` (or `skyzen
  deploy`). It calls `wasm-bindgen` against `target/wasm32-unknown-unknown/debug/stow_edge.wasm`,
  so the `wasm-bindgen` generator embedded in `skyzen-cli` MUST match
  `wasm-bindgen` in stow's `Cargo.lock` (skyzen-cli 0.3.0 ships
  `=0.2.120`, same as the lockfile). When you bump `wasm-bindgen`
  in stow, reinstall a matching `cargo install skyzen-cli` afterwards.

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
- New columns in `artifacts` go in `edge/src/sql/insert_artifact.sql`
  AND `edge/src/db.rs::insert_artifact_record`'s `bind` chain — keep
  these two in sync. Old D1s migrate via
  `edge/src/db.rs::ensure_artifact_table_columns`.
- New scheduler queue columns go in
  `edge/src/scheduler/schema.sql`,
  `edge/src/scheduler/queue.rs::ensure_schema` (forward migration
  branch), `edge/src/scheduler/queue.rs::migrate_queue_schema` (full
  rebuild branch), `TaskRow`, the SELECT column list in
  `claim_dispatchable_tasks`, and the INSERT in `enqueue`.

## Testing changes locally

End-to-end mock setup is documented in
[`docs/MOCK.md`](docs/MOCK.md). For unit tests:

```sh
cargo test --workspace --exclude stow-edge        # host crates
cargo test -p stow-edge --target aarch64-apple-darwin  # edge unit tests run on host (the crate's .cargo/config pins wasm32, so override the target)
```

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
