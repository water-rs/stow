# stow CLI usage

One executable, installed as `stow`, `stow-cli` and `cargo-stow`, with
three roles: a cargo driver (`stow check|build|test|predict`), a setup
and maintenance CLI (`stow setup|update|status|stats|clean|index|check-artifact|fetch-artifact`),
and the hidden `rustc`/`cc` wrapper cargo invokes. The operator CLI,
`stow-admin`, is documented in [ADMIN.md](ADMIN.md).

| Command | Arguments and flags |
|---|---|
| `stow check`, `stow build`, `stow test`, `stow predict` | `--silent-compatible-upgrades`, `--no-stow-resolver`, `--sandbox`, `--sandbox-deny-network`, then any cargo arguments |
| `stow setup` | `--github-env` |
| `stow update` | — |
| `stow status` | — |
| `stow stats` | `--json` |
| `stow clean` | — |
| `stow index refresh` | `--target <triple>`, `--rustc-version <version>` |
| `stow index status` | — |
| `stow check-artifact` | `<target> <rustc_version> <c_metadata>` |
| `stow fetch-artifact` | `<target> <rustc_version> <c_metadata> <output_path> <crate_name>` |
| `stow --version`, `stow --help` | — |

Everything after the stow flags of a cargo-driver command is passed to
cargo unchanged, so `stow build --release -p foo` is `cargo build
--release -p foo` with stow in front.

## Configuration

Stow needs to know two things before any subcommand can use the public
cache: where the edge worker lives, and which signature trust mode the CLI
should run in. See [`CONFIG.md`](CONFIG.md) for the file format and
[`ENVIRONMENT.md`](ENVIRONMENT.md) for the env-var equivalents.

## `stow check` / `build` / `test`

Drop-in replacements for `cargo check|build|test`. Stow resolves your
dependencies against the signed index slice it caches locally, prefetches
the covered bundles within a short pre-cargo budget
(`STOW_CACHE_BUDGET_SECS`), and runs cargo with its wrapper in front of
every rustc call. The wrapper serves each unit from the local cache, then
from the public cache, and otherwise lets rustc compile it and stores the
result locally. Units it compiled are reported as misses after cargo
exits. When the public cache cannot help — zero coverage, a nightly
toolchain, an unreachable edge or registry — the build is plain cargo
plus the local cache; it never fails because the cache was unavailable.

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

`--sandbox` (experimental) runs the cargo build inside a heel sandbox:
cargo, rustc, every build script, proc-macro and linker it spawns are cut
off from the machine outside a declared grant set — the workspace and the
target directory are read/write (writes under the target directory only;
sources stay read-only), the toolchain, cargo registry and stow's wrapper
shims are read, credentials files (`credentials`/`credentials.toml`) and
the home directory are never granted, the clipboard is denied, and the
environment is an allowlist. Stow fetches dependencies first, then the
sandboxed cargo runs offline; a sandbox that cannot be set up fails the
command — there is no unsandboxed fallback.

`--sandbox-deny-network` goes further and denies the build all network
access: the only channel out of the sandbox is the socket the rustc
wrapper uses to reach the supervising stow process.

```sh
stow build --sandbox
stow build --sandbox-deny-network
```

The same switches exist in the config file, so an `experimental` table
enables them for every cargo-running command:

```toml
[experimental]
sandbox = true
sandbox_deny_network = true
```

## `stow predict`

Read-only cache-coverage analysis. It posts nothing and enqueues nothing:
the dependency graph never leaves the machine, and the command is safe to
run in a loop or a script.

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
the lockfile unwalkable because the crates.io index or a git dependency
is not in the local cargo cache yet — exits non-zero with the reason.
Passing `--target <triple>` analyzes a target the host cannot compile
for.

The graph the analysis reads is cargo's own: stow re-runs the wrapped
subcommand with `--unit-graph -Z unstable-options` and projects the
units it reports. `-Z` is unlocked on that one child process with
cargo's channel override (`__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS=nightly`),
which cargo honors but rustc never reads — cfg evaluation stays exactly
what the user's stable toolchain sees. A user-set `RUSTC_BOOTSTRAP`
passes through untouched; an `[unstable]` table or `CARGO_UNSTABLE_*`
variable in the user's config is an error on a stable toolchain, since
the query would honor it while the real build ignores it.

## `stow setup`

Writes (or augments) `$CARGO_HOME/config.toml` — cargo's user-level
configuration, `~/.cargo/config.toml` by default — so every Cargo
invocation on the machine transparently routes through stow's `rustc`
and `cc` wrappers. Run it once per machine; it's idempotent and
preserves unrelated keys.

The wrapper shims live inside the cargo home itself —
`$CARGO_HOME/stow/shims/<key>/`, where `<key>` is derived from the
stow binary's path — so the paths written into `config.toml` survive
reboots, two stow installs never point the same shim at different
binaries, and an isolated `CARGO_HOME` isolates its shims too.

The `[env]` compiler entries are scoped the way the `cc` crate reads
its toolchain variables: the shims are written under
`CC_<host triple>` / `CXX_<host triple>` rather than bare `CC`/`CXX`,
so other targets (`*-windows-gnu`, `wasm32`, cross builds) keep the
compiler cc-rs resolves for them. `STOW_REAL_CC`/`STOW_REAL_CXX` are
written only when a toolchain was already configured; otherwise each
shim resolves the platform's compiler per invocation — the way the
`cc` crate does — so the wiring never goes stale. On an msvc target
that means `find_msvc_tools` for `cl.exe` with the toolchain
environment applied to the child; nothing is persisted — no
`PATH`/`LIB`/`INCLUDE` snapshot, no absolute `cl.exe`.

On Linux, `stow setup` also makes mold available: unless the
configuration already selects a reachable mold, it downloads the pinned,
checksummed mold release into stow's per-user tools directory and
writes the linker wiring into `config.toml` — a `cfg(target_os = "linux")` table
whose rustflags carry `-fuse-ld=mold`, plus an `[env]` `COMPILER_PATH`
entry pointing at the managed install so the compiler driver finds
`ld.mold`. The install path travels in the environment, not in a
rustflag, because every link option reaches the compile key and the
cache keys linked units on `-fuse-ld=mold` alone. An existing
`build.rustflags` is carried into the written table — cargo uses it
only when no matching `target.*` table carries flags, so it would
silently stop applying otherwise.

On Linux the setup also **records the link resolution** into the local
state database: the `rustc --print cfg` evaluation and the driver mold
probe a first build would pay are settled once, so a project with no
cargo configuration of its own builds warm from its first `stow build`.
The record is keyed on the toolchain (`rustc -vV`), the target, the
existing cargo config documents, the environment inputs the resolution
reads (`PATH` included), and the witnessed driver and `ld.mold` files —
changing any of them re-resolves instead of serving a stale answer, and
rows under keys that stopped being asked are pruned after 30 days. To
reset it, rerun `stow setup`, or
remove the state database with the rest of the local cache (`stow
clean`).

`stow check`/`build`/`test` work without setup: on Linux, when the cargo
configuration does not already select a reachable mold, they provision
the managed install and pass the same selection to cargo as `--config`
overrides for that one invocation — identical compile keys to the setup
path, nothing written to disk. A Linux build that cannot link with mold
still refuses to run.

`stow setup --github-env` skips the file and instead prints the same
wiring as `KEY=VALUE` lines (plus the resolved `STOW_EDGE_URL` /
`STOW_VERIFY_MODE`), for CI systems that configure the job environment —
the composite action below appends it to `$GITHUB_ENV`. The linker
selection cannot be expressed this way (env rustflags would replace the
project's configured rustflags wholesale), so a job on Linux also runs
plain `stow setup`, which writes the mold selection into the runner's
`$CARGO_HOME/config.toml`.

## `stow update`

Updates this install to the latest stow-cli release. The shell and
PowerShell installers write a cargo-dist install receipt
(`stow-cli-receipt.json`) recording the install prefix and repository;
`stow update` reads it, downloads the new release's own installer, and
runs it against the recorded prefix — then re-materializes the wrapper
shims so they keep resolving to the fresh binary. A binary that was not
installed by the installer (a `cargo install` or source build has no
receipt) refuses with the reason instead of clobbering itself.

GitHub API calls for the release lookup accept a token from
`STOW_CLI_GITHUB_TOKEN`, `GITHUB_TOKEN`, or `GH_TOKEN` — only useful
against rate limits or a private mirror.

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
`RUSTC_WRAPPER`, `CC_<runner triple>`, `CXX_<runner triple>`,
`CMAKE_C_COMPILER_LAUNCHER`, `CMAKE_CXX_COMPILER_LAUNCHER`,
`STOW_EDGE_URL`, and `STOW_VERIFY_MODE` into `$GITHUB_ENV`
(`STOW_REAL_CC`/`STOW_REAL_CXX` too, when the runner already had a
toolchain configured) — then also
runs plain `stow setup` — the linker selection cannot ride in the job
environment (env rustflags would replace a project's configured
rustflags wholesale), so it is written into the runner's
`$CARGO_HOME/config.toml`, including the managed mold install on Linux.

The action adds no credential to the consuming repository, and a run
where the edge is unreachable or the toolchain unsupported still builds
— the CLI falls back to plain cargo. Because dependency artifacts come
from the shared cache rather than the per-repo Actions cache,
`Swatinem/rust-cache` is no longer needed for dependency artifacts.

## `stow status`

Prints the wrapper configuration `stow setup` wrote into the global
cargo config, any stale per-project wiring an older stow left in an
ancestor `.cargo/config.toml` (`stow setup` removes it), plus rolling
cache-hit counters from the local SQLite
stats DB.

```
config: ~/.cargo/config.toml
rustc-wrapper: ~/.cargo/stow/shims/<key>/stow-rustc-wrapper
cc: ~/.cargo/stow/shims/<key>/stow-cc
cxx: ~/.cargo/stow/shims/<key>/stow-cxx
cc-launcher: ~/.cargo/stow/shims/<key>/stow-cc-launcher
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

Removes the whole cache directory (`STOW_CACHE_DIR`, `cache_dir` in the
config file, or `~/.stow`): every locally built and fetched artifact,
the cached index slices, the state database (`state-v3.sqlite3`, which
holds the local hit counters and the recorded link resolution) and
`stats.json`. It does not touch the wrapper shims under
`$CARGO_HOME/stow/shims/`, the managed mold install, the config file, or
`$CARGO_HOME/config.toml`.

## The local cache

Every dependency stow serves or compiles goes through one cache per
machine, shared by every project, worktree and target directory.

- **Location.** `<cache_dir>/cache/<rustc version>/bundles/v3/<target>/<c_metadata>/`,
  where `<cache_dir>` is `STOW_CACHE_DIR`, else `cache_dir` in the config
  file, else `~/.stow`. Index slices live under `<cache_dir>/index/`, the
  state database and `stats.json` directly in `<cache_dir>`.
- **What goes in.** Every bundle fetched from the public cache, and every
  clean local compile of a crates.io dependency that produces an rlib,
  dylib or proc-macro without custom codegen flags, in any profile.
  Workspace members, path and git dependencies, binaries and build-script
  runs are not stored.
- **How it is keyed.** By the same stable compile key the public cache
  uses, so a crate compiled in one project is a hit in another that
  resolves it identically, regardless of where either checkout lives.
- **Copy-on-write.** Hits are placed in `target/` as reflinks on APFS,
  Btrfs, XFS and ReFS, and as copies elsewhere.
- **Size and eviction.** `STOW_ARTIFACT_CACHE_MAX_BYTES`
  (`artifact_cache_max_bytes` in the config file, default 20 GiB) bounds
  each rustc version's cache. After an insert pushes it over, the least
  recently used entries are deleted; a hit refreshes an entry.
- **One rustc at a time.** When a build runs under a different rustc
  version than the previous one, the other versions' caches are deleted
  in the background (a version another running build is using is kept).
  Switching toolchains back and forth therefore starts each switch cold.
- **Trust.** Local entries are trusted because this machine compiled
  them. They are never uploaded and never signature-checked; fetched
  entries are verified once, when they are downloaded.

### Offline

With no network, or with GHCR or the edge unreachable, a build still
serves every unit the local cache holds and stores every unit it
compiles; the rest compile locally. A cached index slice is used as-is
when the registry cannot be reached. After `circuit_trip_threshold`
consecutive edge failures (default 5) the wrapper stops trying the
network for `circuit_reset_secs` (default 60); local hits continue.
Misses that could not be reported are kept and sent by a later build.

Expect the first units of an offline build to be slower than plain
cargo: with no cached index slice, units that miss locally wait for the
index fetch to give up, and with a cached slice each unit already
downloading waits out `request_timeout_secs` before the breaker trips.

## `stow index refresh` / `stow index status`

Every coverage decision the CLI makes is read from a signed index slice —
one `index.<target>.<rustc>` OCI artifact per (target, rustc) pair — that
`stow check`/`build`/`test` fetch, verify and cache under
`~/.stow/index/<target>/<rustc>/` on demand. `stow index refresh` does the
fetch explicitly for the rustc it probes (or for `--target` /
`--rustc-version` when given) and prints the resolved tag, row count, and
manifest digest. `stow check`/`build`/`test` serve a cached pointer
as-is within `STOW_INDEX_REFRESH_SECS` (default 600,
`index_refresh_secs` in the config file); `stow index refresh` ignores
the interval. Either way one manifest request revalidates the digest
and the slice re-downloads only on change. With no cached slice and the
registry unreachable, refresh fails hard — the same condition the
wrapper degrades to plain cargo over.

`stow index status` lists every verified slice in the local cache — one
`index:`/`target:`/`rustc-version:`/`rows:`/`fetched-at:`/
`manifest-digest:` block each — or prints `no cached index slices`.

## `stow check-artifact <target> <rustc_version> <c_metadata>`

Looks the exact artifact up in the verified index slice for `target` and
`rustc_version` (fetching the slice if needed) and prints `status:
present` with the crate, version and bundle digest, or `status: absent`,
plus the slice's manifest digest. Downloads no bundle.

## `stow fetch-artifact <target> <rustc_version> <c_metadata> <output_path> <crate_name>`

Resolves the artifact the same way, downloads its bundle through the
edge, checks the bytes against the digest the index pins, and writes the
bundle tar to `output_path`. For inspection; builds do not need it.

## Hidden subcommands

Not for users:

- `stow rustc <rustc> <args>` and `stow cc <compiler> <args>` — how cargo
  and the C/C++ shims invoke the wrapper.
- `stow __drain-misses <target_dir>` — posts the misses a finished
  build's wrappers journaled under `target_dir`; the driver or a later
  wrapper spawns it detached.
- `stow __purge-cache-dir <path>...` — deletes the cache directories of
  rustc versions no longer in use, spawned detached when a build switches
  rustc.

## `cargo-stow` and `stow-cli`

`cargo-stow` is the cargo plugin entry point: `cargo stow build` is
`stow build`. `stow-cli` is the same program under the package's name.
All three binaries behave identically.

## `stow-admin`

The operator CLI is not for users. See [ADMIN.md](ADMIN.md).
