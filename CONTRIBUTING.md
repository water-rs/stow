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
  so the `wasm-bindgen-cli-support` version pinned in
  `skyzen/cli/Cargo.toml` MUST match `wasm-bindgen` in stow's
  `Cargo.lock` (e.g., both at `=0.2.120`). When you bump `wasm-bindgen`
  in stow, do `cargo install --path skyzen/cli --force` afterwards.

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
cargo test --workspace --exclude stow-edge   # host crates
cd edge && cargo test                        # wasm-side tests run on host (with #[cfg(target_arch="wasm32")] gates)
```

## Schema-evolving changes

Any change that alters wire types in `types/src/api.rs` invalidates the
prebuilt `edge/stable-worker.js` + `edge/stable-worker_bg.wasm`
artifacts. Re-run `skyzen dev` once to repackage; the next `wrangler
dev`/`wrangler deploy` will use the fresh bundle.

## Commit hygiene

Follow the existing repo style: short imperative subject; body
explains the *why* not the *what*. Don't lump trust-model changes with
unrelated fixes.
