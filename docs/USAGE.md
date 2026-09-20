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
direct deps, nightly toolchain, unreachable edge), it transparently falls
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

`predict` runs the same graph analysis as `stow check`, so the misses it
finds are submitted to the scheduler the same way (proof-of-work
admission, best effort). A prediction that cannot be computed — stow not
configured, the edge unreachable, `cargo metadata --offline` unable to
resolve the lockfile because the registry index or a git dependency is not
in the local cargo cache yet — exits non-zero with the reason. Passing
`--target <triple>` analyzes — and preheats — a target the host cannot
compile for; the `Preheat` workflow in this repository uses that to warm
the cache for every `water-rs` repository on every CI target from one
Linux runner.

## `stow setup`

Writes (or augments) `.cargo/config.toml` in the current directory so
Cargo invocations transparently route through stow's `rustc` and `cc`
wrappers. Use this once per project; it's idempotent.

The wrapper shims live under the per-user data directory —
`~/Library/Application Support/stow/tools` on macOS,
`~/.local/share/stow/tools` on Linux, `%LOCALAPPDATA%\stow\tools` on
Windows — so the paths written into `.cargo/config.toml` survive reboots.

`stow setup --github-env` skips the file and instead prints the same
wiring as `KEY=VALUE` lines (plus the resolved `STOW_EDGE_URL` /
`STOW_VERIFY_MODE`), for CI systems that configure the job environment —
the composite action below appends it to `$GITHUB_ENV`.

## GitHub Actions

The composite action at the repository root installs the pinned
`stow-cli` release for the runner's target and exports the wrapper
environment for the whole job, so an unchanged `cargo test` step is
accelerated:

```yaml
- uses: water-rs/stow@main
- run: cargo test
```

| Input | Default | Purpose |
|---|---|---|
| `version` | `latest` | `stow-cli` release to install — `latest` (the newest stable release that already carries its archives), a bare version (`1.2.3`), or the full `stow-cli-v1.2.3` tag. |
| `edge-url` | `https://stow.waterui.dev` | Edge worker URL, exported as `STOW_EDGE_URL`. |
| `verify-mode` | `github-ci` | Signature verification mode, exported as `STOW_VERIFY_MODE`. `mock-key` additionally needs `STOW_MOCK_PUBLIC_KEY_PATH` in the job environment. |

The action downloads `stow-cli-<target>.tar.xz` (`.zip` on Windows) and
its `.sha256` from the `stow-cli-v<version>` GitHub Release, verifies
the checksum — a failed download or checksum fails the job — unpacks
`stow`, `stow-cli`, and `cargo-stow` onto `PATH`, and writes
`RUSTC_WRAPPER`, `STOW_REAL_CC`, `STOW_REAL_CXX`, `CC`, `CXX`,
`CMAKE_C_COMPILER_LAUNCHER`, `CMAKE_CXX_COMPILER_LAUNCHER`,
`STOW_EDGE_URL`, and `STOW_VERIFY_MODE` into `$GITHUB_ENV`.

The action adds no credential to the consuming repository, and a run
where the edge is unreachable or the toolchain unsupported still builds
— the CLI falls back to plain cargo. Because dependency artifacts come
from the shared cache rather than the per-repo Actions cache,
`Swatinem/rust-cache` is no longer needed for dependency artifacts.

## `stow status`

Prints the project's wrapper configuration plus rolling cache-hit
counters from the local SQLite stats DB.

```
config: /path/to/.cargo/config.toml
rustc-wrapper: ~/.local/share/stow/tools/stow-rustc-wrapper
cc: ~/.local/share/stow/tools/stow-cc
cxx: ~/.local/share/stow/tools/stow-cxx
cc-launcher: ~/.local/share/stow/tools/stow-cc-launcher
edge-url: https://stow.waterui.dev
rust-cache: hits=412 misses=87 errors=2
cc-cache: hits=11 misses=3 errors=0
```

## `stow stats`

Prints this install's own cache benefit — served hits, misses, errors,
the CPU time the served artifacts would have cost to compile, and the
bytes downloaded — from `stats.json` and the per-crate counters in the
local state DB. `--json` prints the same counters as JSON.

Nothing leaves the machine: the command reads local counters only. See
[`PRIVACY.md`](../PRIVACY.md) for what the edge records about requests.

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

Operations CLI for cache operators. Not for end users. Nouns then verbs;
`--json` is a global flag (machine-readable stdout instead of the human
table), and every mutating command prints its plan and exits without
acting unless `--yes` is given.

- `stow-admin status` — lane depths, oldest pending age, in-flight builds
  with their GitHub Actions run URLs, and per-target outcomes over the
  trailing 24 h.
- `stow-admin queue list [--status failed] [--target T] [--crate X] [--older-than 24h]`
  — filtered queue rows; `queue retry|cancel|promote|purge` mutate the
  same selection (explicit `--task-id`s or filter flags), printing the
  matched rows first and applying only under `--yes`. `purge` also
  requires `--older-than` so live work can never be swept.
- `stow-admin coverage <crate>[@version] [--target T]` — which servable
  identities exist per CI target, and which targets have none.
- `stow-admin runs failures --since 24h` — classify failed
  `build-crate.yml` runs from their job logs, grouped by failure class.
- `stow-admin artifacts inspect <c_metadata> --target T --rustc-version V`
  — the catalog row plus its OCI bundle manifest;
  `artifacts prune --rustc-version V --yes` deletes a retired toolchain's
  catalog rows (GHCR tags are not deleted).
- `stow-admin cache stats` / `cache clear --prefix <p> --yes` — the
  repository's GitHub Actions cache quota and prefix eviction.
- `stow-admin panic on|off|status` — the anonymous-traffic circuit
  breaker (`on`/`off` are mutations).
- `stow-admin submit --crate-name X --version 1.2.3 --features-json '["default"]' --target aarch64-apple-darwin --rustc-version 1.91.1 --yes`
  — enqueue one specific build task.
- `stow-admin preheat top --target ... --rustc-version ... [--limit 100] --yes`
  — submit the top-N most-downloaded **library** crates' canonical
  feature/version selections. Standalone builds; intended for the base
  library pool.
- `stow-admin preheat binary-overlay --target ... --rustc-version ... [--limit 100] --yes`
  — submit the top-N most-downloaded **binary** crates with
  `preserve_lockfile=true`. The CI runner builds each binary using its
  published `Cargo.lock`, capturing the entire transitive dep closure
  with the same `dependency_c_metadata_json` that `cargo install
  --locked <bin>` would produce on a user's machine. This is the only
  mode that reliably populates the cache for downstream `cargo install
  --locked` runs.
- `stow-admin preheat projects --file preheat/projects.toml --target ... --rustc-version ... --yes`
  — submit one project-source task per `[[project]]` entry of the
  checked-in showcase list. Each entry's `ref_policy` (`latest-tag` or
  `default-branch`) is resolved to an immutable commit with
  `git ls-remote`, then shallow-fetched so the manifest supplies the
  package identity; the submitted task is the same shape as
  `preheat binary-overlay --manifest-path`.
- `stow-admin preheat missed --rustc-version ... [--limit 50] [--since-days 7] [--targets a,b] --yes`
  — promote the top-K most-missed `(crate, version, features)` identities
  from the `stow_cache_misses` Analytics Engine dataset.
- `stow-admin preheat plan <crate>[@version] [--target T]` — dry-run the
  closure expansion a request would produce; enqueues nothing.

Because the cache identity pins the exact stable `rustc_version`, every
stable release invalidates the pool — `release-reheat.yml` polls the
stable channel manifest every two hours and, on a new version,
dispatches `preheat-admin.yml` (with `project=waterui`, the projects
file, and the binary overlay) plus `preheat.yml` automatically.

`stow-admin` requires `STOW_EDGE_URL` and a GitHub credential with push
access to `water-rs/stow` (`GH_TOKEN`/`GITHUB_TOKEN`, or `gh auth login`). See
[`ENVIRONMENT.md`](ENVIRONMENT.md).
