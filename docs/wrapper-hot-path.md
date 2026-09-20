# Stow rustc-wrapper hot path

Cargo invokes the wrapper *once per compilation unit* — for a real workspace
that's hundreds of times per `cargo build`. Every millisecond added here is
multiplied by N, so this path is performance-load-bearing.

## What runs per invocation

Trace this with `STOW_TRACE_FILE=/tmp/stow.json stow check …` and look at the
`stow.wrapper.invoke` span and its children.

1. **Process spawn.** `cargo` execs the shell shim under the per-user
   tools dir (`~/Library/Application Support/stow/tools/` on macOS,
   `~/.local/share/stow/tools/` on Linux), which `exec`s the stow binary
   with `rustc <args...>`. Unavoidable.
2. **Tokio runtime build** (`cli/src/lib.rs::run`). Wrapper invocations use
   `current_thread` since there is at most one concurrent network task; only
   `stow check` itself uses `multi_thread`.
3. **Tracing init** (`should_install_tracing` in `cli/src/lib.rs`). Skipped
   unless `RUST_LOG` or `STOW_TRACE_WRAPPED_COMPILERS` is set.
4. **`StowConfig::load`** (`cli/src/config.rs`). Reads `STOW_CONFIG_BLOB` env
   first; the parent `stow check` writes it once and every wrapper invocation
   reads it instead of re-parsing `~/.config/stow/config.toml`.
5. **`ParsedRustcArgs::parse`** (`types/src/rustc.rs`). In-memory arg walk; no
   I/O.
6. **`prepare_local_cache`** (`cli/src/artifact_cache.rs`). Opens the local
   SQLite pool and walks the artifact cache for the resolved rustc lease.
7. **Cache lookup** (`load_cached_bundle`). One SQLite query against the
   exact-key index.
8. **On exact-key hit:** `verify_cached_bundle_signature` runs once per unique
   bundle, then materializes outputs into the cargo target dir via
   `record_materialized_bundle_outputs` (reflink or copy).
9. **On exact miss:** `download_raw_bundle` POSTs to
   `/api/v1/artifacts/semantic` via zenwave, verifies the signature, persists
   the bundle, then materializes.
10. **Fall-through:** if no cache is available, exec the real `rustc`.

## Things that must never run on this path

Adding any of these to the per-invocation flow will cause cascading slowdowns
in `cargo check`/`cargo build`. Keep them at `stow check` startup, on
`setup`, or at install time.

* **TLS handshake against a fresh remote.** Cache the connection pool in the
  parent if needed, or batch via prefetch.
* **Sigstore TUF root refresh.** `SigstoreTrustRoot::new` is currently invoked
  only inside `verify_*` and only on the first verification within a single
  process. Do not move it to startup.
* **Full SQLite migration runs.** `state_db::connect` is fast on warm pools
  but should not call `ensure_migrations` on every invocation.
* **`cargo metadata`.** Already removed; do not re-add. Use lockfile parsing
  via `workspace_deps::resolve_lockfile_graph` instead.
* **`rustc -vV` / `rustc --version` probes.** The parent `stow check`
  unconditionally sets `STOW_PUBLIC_CACHE_RUSTC_VERSION` /
  `STOW_PUBLIC_CACHE_TARGET` so the wrapper short-circuits in
  `rustc_args::detect_rustc_*`.
* **Reading `~/.config/stow/config.toml`.** Pass via `STOW_CONFIG_BLOB`.

## Measuring overhead

```sh
rm -rf "$STOW_CACHE_DIR" ~/.cache/stow /tmp/tokei
git clone --depth 1 https://github.com/XAMPPRocky/tokei /tmp/tokei
STOW_TRACE_FILE=/tmp/stow-cold.json stow check --manifest-path /tmp/tokei/Cargo.toml
# repeat without removing cache for warm path
STOW_TRACE_FILE=/tmp/stow-warm.json stow check --manifest-path /tmp/tokei/Cargo.toml
```

Open the JSON in chrome://tracing or perfetto.dev. The interesting span tree
roots at `stow.startup`. The total span time should account for ≥80% of wall
time; if it doesn't, instrument the missing piece before optimizing.
