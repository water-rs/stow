# Stow CLI usage

The user-facing binary is `stow`. It ships three personalities in one
executable: a `cargo` driver (`stow check|build|test|predict|preheat`), a
maintenance/setup CLI (`stow setup|status|stats|index|clean|check-artifact|fetch-artifact`),
and a hidden `rustc`/`cc` wrapper invoked by Cargo through `RUSTC_WRAPPER`.

## Configuration

Stow needs to know two things before any subcommand can use the public
cache: where the edge worker lives, and which signature trust mode the CLI
should run in. See [`CONFIG.md`](CONFIG.md) for the file format and
[`ENVIRONMENT.md`](ENVIRONMENT.md) for the env-var equivalents.

## `stow check` / `build` / `test`

Drop-in replacements for `cargo check|build|test`. Stow inspects your
workspace, resolves which prebuilt artifacts cover your dependencies
against the signed index slice it caches locally, prefetches those
bundles through the edge worker, and lets Cargo compile only the
remaining units. When stow cannot accelerate (e.g. zero coverage,
nightly toolchain, unreachable edge), it transparently falls back to
vanilla Cargo — the command never fails just because the cache
was unavailable.

`--no-stow-resolver` skips the lockfile takeover: by default stow
synthesizes a cache-optimized `Cargo.lock` locally — every package pins
a version the index covers — and validates it with a `cargo metadata
--locked` dry run, so a synthesis that violates the workspace's semver or
feature requirements is discarded and cargo's own resolver runs instead.
Pass the flag to skip the takeover entirely.

```sh
stow check --manifest-path /path/to/project/Cargo.toml
stow build --release --bin myapp
stow test
```

`--silent-compatible-upgrades` opt-in: when stow's index analysis
recommends a semver-compatible patch upgrade that would gain cached
artifacts (e.g., `regex 1.10.6 -> 1.12.3`), apply it silently in a
workspace mirror instead of prompting. Recommended for CI.

```sh
stow check --silent-compatible-upgrades --manifest-path Cargo.toml
```

## `stow predict`

Read-only cache-coverage analysis. It posts nothing and enqueues nothing:
the dependency graph never leaves the machine, and the command is safe to
run in a loop or a script. `stow preheat` below is the half that submits
misses to the scheduler.

Prints two numbers:

- **index has rows for X / Y transitive dependencies** — an upper bound
  reflecting what the signed index slice covers. Whether each row is
  *usable* at runtime depends on the user's exact
  `dependency_c_metadata_json` resolution matching the cached entry's.
- **direct deps fully covered (top-crate fast path) M / N** — the strict
  tier. At 100% the workspace qualifies for the closure-materialization
  path that pre-cooks every direct dep and lets Cargo compile only the
  top crate; that path is experimental and engages only when
  `STOW_ENABLE_PREBUILT_DEPS` is set, so on a default install this line
  reports the ceiling the regular per-unit inject path could reach, and
  coverage short of 100% is served per unit rather than all-or-nothing.

```sh
stow predict --manifest-path /path/to/project/Cargo.toml
```

The output also includes recommended compatible upgrades — direct deps
where a newer semver-compatible patch would push the dep into the cached
set.

`predict` runs the same local index analysis as `stow check`. A prediction
that cannot be computed — stow not configured, the registry unreachable,
`cargo metadata --offline` unable to resolve the lockfile because the
crates.io index or a git dependency is not in the local cargo cache yet —
exits non-zero with the reason. Passing `--target <triple>` analyzes a
target the host cannot compile for.

## `stow preheat`

The same analysis as `predict`, followed by a request that the public cache
build what it cannot serve for this workspace. This is the half that
writes: the dependency graph is posted to `/api/v1/admissions`, which mints
proof-of-work admissions, and the client redeems them at
`/api/v1/enqueue`. Both steps are best effort — an admission that cannot be
redeemed before its challenge expires is simply minted again on the next
run.

```sh
stow preheat --manifest-path /path/to/project/Cargo.toml
```

Unlike `check` and `build`, `preheat` waits for the redemptions: there is
no cargo run for a drain to delay, and submitting the misses is the whole
point of the command.

Passing `--target <triple>` preheats a target the host cannot compile for.
The `Preheat` workflow in this repository uses that to warm the cache for
every `water-rs` repository on every CI target from one Linux runner.

## `stow setup`

Writes (or augments) `.cargo/config.toml` in the current directory so
Cargo invocations transparently route through stow's `rustc` and `cc`
wrappers. Use this once per project; it's idempotent.

The wrapper shims live under the per-user data directory —
`~/Library/Application Support/stow/tools` on macOS,
`~/.local/share/stow/tools` on Linux, `%LOCALAPPDATA%\stow\tools` on
Windows — so the paths written into `.cargo/config.toml` survive reboots.

On Linux, `stow setup` also makes mold available: unless the project
already selects a reachable mold, it downloads the pinned, checksummed
mold release into the same tools directory and writes the linker wiring
into `.cargo/config.toml` — a `cfg(target_os = "linux")` table whose
rustflags carry `-fuse-ld=mold`, plus an `[env]` `COMPILER_PATH` entry
pointing at the managed install so the compiler driver finds `ld.mold`.
The install path travels in the environment, not in a rustflag, because
every link option reaches the compile key and the cache keys linked units
on `-fuse-ld=mold` alone. mold is required on Linux: a `stow
check`/`build`/`test` whose configuration does not select a reachable
mold refuses to run.

`stow setup --github-env` skips the file and instead prints the same
wiring as `KEY=VALUE` lines (plus the resolved `STOW_EDGE_URL` /
`STOW_VERIFY_MODE`), for CI systems that configure the job environment —
the composite action below appends it to `$GITHUB_ENV`. The linker
selection cannot be expressed this way (env rustflags would replace the
project's configured rustflags wholesale), so a job on Linux also needs
mold selected in its own `.cargo/config.toml`.

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

Removes the local stow cache directory (`$STOW_CACHE_DIR`, or `~/.stow`
by default; see [`ENVIRONMENT.md`](ENVIRONMENT.md)). Does NOT remove the
local stats DB or wrapper shims.

## `stow index refresh` / `stow index status`

Every coverage decision the CLI makes is read from a signed index slice —
one `index.<target>.<rustc>` OCI artifact per (target, rustc) pair — that
`stow check`/`build`/`test` fetch, verify and cache under
`~/.stow/index/<target>/<rustc>/` on demand. `stow index refresh` does the
fetch explicitly for the rustc it probes (or for `--target` /
`--rustc-version` when given) and prints the resolved tag, row count, and
manifest digest. Within `STOW_INDEX_REFRESH_SECS` (default 600,
`index_refresh_secs` in the config file) a cached pointer serves as-is
and a refresh is a no-op; past it one manifest request revalidates the
digest and the slice re-downloads only on change. With no cached slice
and the registry unreachable, refresh fails hard — the same condition
the wrapper degrades to plain cargo over.

`stow index status` lists every verified slice in the local cache — one
`index:`/`target:`/`rustc-version:`/`rows:`/`fetched-at:`/
`manifest-digest:` block each — or prints `no cached index slices`.

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
  library pool. A ranked crate whose newest release ships no library
  target (a bin-only crate that slipped into the ranking) is resolved
  as a name source instead: its `.crate` tarball is unpacked and
  `cargo metadata --filter-platform` enqueues its crates.io graph,
  exactly like `preheat binary`.
- `stow-admin preheat binary <crate>[@version] [--targets a,b] [--rustc-version ...] --yes`
  — preheat one named **binary** crate's dependency graph from
  crates.io: the `.crate` tarball is unpacked and `cargo metadata
  --filter-platform` runs once per CI target — every crates.io node an
  ordinary crate task at its resolved feature set, with its crates.io
  dependencies as `depends_on` edges. The binary's own package is a name
  source, never a task. The published tarball decides the resolution —
  a release that ships a `Cargo.lock` unpacks with it in place, so the
  resolve lands on the pins `cargo install --locked` reproduces and
  those pins bake into each task's `version` and `features_json`; one
  that ships none resolves fresh, what plain `cargo install` does.
  `preserve_lockfile` stays `false` on every derived task — on the
  runner it names the task crate's own lockfile, not the source
  binary's. A crate with no binary target is refused and pointed at
  `preheat top`. `--rustc-version` defaults to the scheduler's current
  stable channel version, `--targets` to every CI target.
- `stow-admin preheat top-binaries --rustc-version ... [--targets a,b] [--limit 100] --yes`
  — resolve the top-N most-downloaded **binary** crates exactly the way
  `preheat binary` resolves one: name sources, never tasks of their
  own. The emitted tasks carry each binary's download count as their
  queue priority. A binary that fails to resolve is reported and
  skipped; `--targets` defaults to every CI target.
- `stow-admin preheat missed --rustc-version ... [--limit 50] [--since-days 7] [--targets a,b] --yes`
  — promote the top-K most-missed `(crate, version, features)` identities
  from the `stow_cache_misses` Analytics Engine dataset.
- `stow-admin preheat projects submit [--file preheat/projects.toml] --rustc-version ... [--targets a,b] --yes`
  — resolve every repository the reviewed `preheat/projects.toml` lists:
  each is shallow-cloned, its committed `Cargo.lock` deleted so cargo
  re-resolves the latest semver-compatible versions, and `cargo metadata
  --filter-platform` runs once per CI target. Every crates.io node in
  the resolve is enqueued as an ordinary crate task at its resolved
  feature set — feature sets are never merged — with its crates.io
  dependencies as `depends_on` edges at the same `(target,
  rustc_version)`. A repository that fails to resolve is reported and
  skipped; a project contributes names and feature sets, never version
  pins.
- `stow-admin preheat projects generate [--limit 200] [--min-stars 250] [--output preheat/projects.toml]`
  — rebuild the reviewed list from GitHub's most-starred Rust
  repositories: a candidate is admitted when its git tree carries a
  `Cargo.lock` beside a `Cargo.toml`, shallowest first, which is why
  libraries (they commit no lockfile) drop out to the download-ranked
  lane. Prints every rejection with its reason and writes the file;
  `preheat-projects.yml` runs this weekly and opens the pull request.
- `stow-admin preheat plan <crate>[@version] [--target T]` — dry-run the
  closure expansion a request would produce; enqueues nothing.
- `stow-admin index export --target T --rustc-version V --out <file>` /
  `index publish --file <file> --target T --rustc-version V` /
  `index targets` — export one signed index slice from the edge's admin
  endpoint, push it to GHCR (mock deploys delegate to
  `stow-mock-registry publish-index`), and list the `(target, rustc)`
  pairs a published index covers. `index-publish.yml` runs this loop
  after every `build-crate` wave.

None of this has to be run by hand. `preheat-cron.yml` dispatches the
whole wave — `preheat top`, `preheat top-binaries`, the
`preheat.yml` org pass, and `preheat projects submit` — once per
UTC day and immediately whenever the stable channel moves, since the
cache identity pins the exact stable `rustc_version` and every release
invalidates the pool. Re-submitting the same list is deliberately cheap:
the scheduler deduplicates on task identity, leaves completed tasks
completed, and retires pending tasks the catalog already covers, so each
wave builds only what is missing or previously failed.

`stow-admin` requires `STOW_EDGE_URL` and a GitHub credential with push
access to `water-rs/stow` (`GH_TOKEN`/`GITHUB_TOKEN`, or `gh auth login`).
`preheat projects generate` is the one exception — it touches only
GitHub, never the edge. See [`ENVIRONMENT.md`](ENVIRONMENT.md).
