# Stow rustc-wrapper hot path

Cargo invokes the wrapper *once per compilation unit* — for a real workspace
that's hundreds of times per `cargo build`. Every millisecond added here is
multiplied by N, so this path is performance-load-bearing.

## What runs per invocation

Trace this with `STOW_TRACE_FILE=/tmp/stow.json stow check …` and look at the
`stow.wrapper.invoke` span and its children.

1. **Process spawn.** `cargo` execs the shim under the cargo home
   (`$CARGO_HOME/stow/shims/<key>/`, one directory per stow binary),
   which is the stow binary itself under a wrapper name — a symlink on
   Unix, a copy on Windows — running as `rustc <args...>`. Unavoidable.
2. **Tokio runtime build** (`cli/src/lib.rs::run`). Wrapper invocations use
   `current_thread` since there is at most one concurrent network task;
   every non-wrapper command (`stow check`, `stow build`, `stow predict`,
   the rest) gets `multi_thread`.
3. **Tracing init** (`install_tracing` in `cli/src/lib.rs`). Every process
   but the daemon installs a subscriber, so a wrapper can print the
   warnings the daemon returns to it. A wrapper holds it to the default
   `warn` filter, with no trace file, unless `STOW_TRACE_WRAPPED_COMPILERS`
   is set to a non-`0` value — `RUST_LOG` alone does not reach wrapped
   invocations. Non-wrapper commands always read `RUST_LOG`.
4. **Session lookup** (`SessionLink::from_env` in `cli/src/daemon/client.rs`).
   `STOW_SESSION` names the build's session on the per-user daemon. Without
   it the wrapper's first request finds the session of the cargo that
   started it, which the daemon opens from the wrapper's environment when
   there is none. Either way the wrapper hands the invocation to the daemon
   (`delegate_to_daemon` in `cli/src/lib.rs`) and loads no config, opens no
   state database and reads no index.

The wrapper:

1. connects to the daemon — directly, or through the driver's relay from
   inside a sandbox — and sends the invocation as one `Plan` request;
2. exits successfully when the daemon served the unit from the cache, or
   runs the real `rustc` the answer names and reports its result, which the
   session records. The daemon answers the report with a receipt before
   it does any bookkeeping, so the wrapper exits as soon as `rustc` has and
   keeps the build's job slot only as long as the compile;
3. prints what the daemon logged while deciding the request, at `warn` and
   above, which it sends ahead of the answer.

Everything else — the build's config, toolchain, serve map, index slice,
local cache, signature verification and the one connection to the edge —
belongs to the daemon's session for the whole build. A wrapper that cannot
reach the daemon fails the compile; it never decides on its own.

## Things that must never run on this path

Adding any of these to the per-invocation flow will cause cascading slowdowns
in `cargo check`/`cargo build`. Keep them at `stow check` startup, on
`setup`, or at install time.

* **TLS handshake against a fresh remote.** Cache the connection pool in the
  parent if needed, or batch via prefetch.
* **Sigstore TUF root refresh.** `SigstoreTrustRoot::new` already runs where
  it belongs: once at `stow check`/`stow build`/`stow test` startup before
  the prefetch budget clock starts (so a >1s refresh never eats the
  per-artifact allowance), and once lazily on the first verification inside
  a wrapper process. Keep it out of per-unit work.
* **Full SQLite schema passes.** `state_db::connect` is fast on warm pools
  but its column-parity pass should not run on every invocation.
* **`cargo metadata`.** Already removed; do not re-add. Use lockfile parsing
  via `workspace_deps::lockfile_registry_packages` instead.
* **`rustc -vV` / `rustc --version` probes.** The build's session carries the
  toolchain's facts, so a wrapper probes nothing; a probe it is handed
  (`-vV`, `--print`) it runs itself, on the answer the daemon gives.
* **Reading `~/.config/stow/config.toml`.** The build's session carries the
  resolved config, loaded in the daemon.

## Measuring overhead

```sh
rm -rf "$STOW_CACHE_DIR" ~/.cache/stow ~/Library/Caches/stow /tmp/tokei
git clone --depth 1 https://github.com/XAMPPRocky/tokei /tmp/tokei
STOW_TRACE_FILE=/tmp/stow-cold.json stow check --manifest-path /tmp/tokei/Cargo.toml
# repeat without removing cache for warm path
STOW_TRACE_FILE=/tmp/stow-warm.json stow check --manifest-path /tmp/tokei/Cargo.toml
```

Open the JSON in chrome://tracing or perfetto.dev. The interesting span tree
roots at `stow.startup`. The total span time should account for ≥80% of wall
time; if it doesn't, instrument the missing piece before optimizing.