# Stow CLI usage

The user-facing binary is `stow`. It ships three personalities in one
executable: a `cargo` driver (`stow check|build|test|predict`), a
maintenance/setup CLI (`stow setup|status|clean|check-artifact|fetch-artifact`),
and a hidden `rustc`/`cc` wrapper invoked by Cargo through `RUSTC_WRAPPER`.

## Configuration

Stow needs to know two things before any subcommand can use the public
cache: where the edge worker lives, and which signature trust mode the CLI
should run in. See [`CONFIG.md`](CONFIG.md) for the file format and
[`ENVIRONMENT.md`](ENVIRONMENT.md) for the env-var equivalents.

## `stow check` / `build` / `test`

Drop-in replacements for `cargo check|build|test`. Stow inspects your
workspace, asks the edge worker which prebuilt artifacts cover your direct
dependencies, materializes those into Cargo's target dir, and runs Cargo
against the remaining work. When stow cannot accelerate (e.g. uncached
direct deps, nightly toolchain, missing edge URL), it transparently falls
back to vanilla Cargo — the command never fails just because the cache
was unavailable.

```sh
stow check --manifest-path /path/to/project/Cargo.toml
stow build --release --bin myapp
stow test
```

`--silent-compatible-upgrades` opt-in: when stow's edge analysis
recommends a semver-compatible patch upgrade that would gain cached
artifacts (e.g., `regex 1.10.6 -> 1.12.3`), apply it silently in a
workspace mirror instead of prompting. Recommended for CI.

```sh
stow check --silent-compatible-upgrades --manifest-path Cargo.toml
```

## `stow predict`

Dry-run cache-coverage analysis. Prints two numbers:

- **edge has rows for X / Y transitive dependencies** — an upper bound
  reflecting what the edge knows. Whether each row is *usable* at runtime
  depends on the user's exact `dependency_c_metadata_json` resolution
  matching the cached entry's.
- **direct deps fully covered (top-crate fast path) M / N** — the strict
  acceleration tier. When this hits 100%, `stow check` engages the
  closure-materialization path that pre-cooks every direct dep and lets
  Cargo skip compiling them. Anything below 100% falls back to vanilla
  Cargo.

```sh
stow predict --manifest-path /path/to/project/Cargo.toml
```

The output also includes recommended compatible upgrades — direct deps
where a newer semver-compatible patch would push the dep into the cached
set.

## `stow setup`

Writes (or augments) `.cargo/config.toml` in the current directory so
Cargo invocations transparently route through stow's `rustc` and `cc`
wrappers. Use this once per project; it's idempotent.

## `stow status`

Prints the project's wrapper configuration plus rolling cache-hit
counters from the local SQLite stats DB.

```
config: /path/to/.cargo/config.toml
rustc-wrapper: /tmp/stow-tools/stow-rustc-wrapper
CC: /tmp/stow-tools/stow-cc-wrapper
edge-url: https://cache.stow-rs.example
rust-cache: hits=412 misses=87 errors=2
cc-cache:   hits=11 misses=3 errors=0
```

## `stow clean`

Removes the local stow cache directory (`$STOW_CACHE_DIR` or the OS
default; see [`ENVIRONMENT.md`](ENVIRONMENT.md)). Does NOT remove the
local stats DB or wrapper shims.

## `stow check-artifact <target> <rustc_version> <c_metadata>`

HEAD probe against the edge artifact endpoint. Useful for debugging
"is this exact key in cache" questions without actually downloading
the bundle.

## `stow fetch-artifact <target> <rustc_version> <c_metadata> <output_path> <crate_name>`

GETs the OCI bundle for an exact key and writes it to disk. Supports
introspection workflows; the regular wrapper path doesn't need this.

## Hidden subcommands

`stow rustc <real-rustc> <args>` and `stow cc <real-compiler> <args>`
are how Cargo invokes the wrapper. End users should never call these
directly. `stow __purge-cache-dir <paths>` is invoked by the parent
`stow check` when the local cache exceeds its byte budget; never call
it manually.

## `cargo-stow`

A `cargo` plugin entry point. Installing this binary alongside `stow`
lets you run `cargo stow check` instead of `stow check`. Behavior is
identical.

## `stow-admin`

Operations CLI for cache operators. Not for end users.

- `stow-admin submit --crate-name X --version 1.2.3 --features-json '["default"]' --target aarch64-apple-darwin --rustc-version 1.91.1`
  — enqueue one specific build task.
- `stow-admin preheat-t100 --target ... --rustc-version ... [--limit 100]`
  — submit the top-N most-downloaded **library** crates' canonical
  feature/version selections. Standalone builds; intended for the base
  library pool.
- `stow-admin preheat-binary-overlay --target ... --rustc-version ... [--limit 100]`
  — submit the top-N most-downloaded **binary** crates with
  `preserve_lockfile=true`. The CI runner builds each binary using its
  published `Cargo.lock`, capturing the entire transitive dep closure
  with the same `dependency_c_metadata_json` that `cargo install
  --locked <bin>` would produce on a user's machine. This is the only
  mode that reliably populates the cache for downstream `cargo install
  --locked` runs.

`stow-admin` requires `STOW_EDGE_URL` and `SCHEDULER_AUTH_TOKEN`. See
[`ENVIRONMENT.md`](ENVIRONMENT.md).
