# Stow CLI usage

The user-facing binary is `stow`. It ships three personalities in one
executable: a `cargo` driver (`stow check|build|test|predict`), a
maintenance/setup CLI (`stow setup|update|status|stats|index|clean|check-artifact|fetch-artifact`),
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

## Build isolation

Every cargo-running command confines the build — cargo, rustc, every build
script, proc-macro and linker it spawns — at one of four levels. The level
is independent of the cache mode: it holds with the public cache on or off.

| Level | Files | Network | Environment |
| --- | --- | --- | --- |
| `protect` (default except on Windows) | The machine is open except credential stores, which cannot be read, and persistence locations, which cannot be written | Allowed through an audited proxy | Host variables, minus credential variables |
| `strict` (default on Windows) | An allowlist: the workspace and target directory, the toolchain and registry, stow's shims | Allowed through an audited proxy | An allowlist |
| `offline` | As `strict` | None; the only channel out is the socket the rustc wrapper uses to reach stow | An allowlist |
| `off` | No confinement | Unrestricted | Unrestricted |

```sh
stow build                       # protect (strict on Windows)
stow build --isolation strict
stow build --isolation offline
stow build --isolation off
```

The config file sets the default for every cargo-running command; the flag
overrides it:

```toml
[isolation]
level = "strict"
audit_files = 30
```

`protect` does not fetch ahead of the build: cargo runs online inside the
sandbox, with a writable cargo home. `strict` and `offline` fetch
dependencies first and run cargo offline inside.

What `protect` denies is a fixed list:

- Reads of credential stores: SSH and GPG keys and agents, forge and
  registry tokens (`gh`, `glab`, `~/.cargo/credentials*`, `.npmrc`, `.pypirc`,
  `.netrc`, `.git-credentials`, Docker, Terraform, Vault, 1Password and
  `pass` data), cloud-provider configuration (AWS, Azure, gcloud, kube, OCI,
  DigitalOcean, Heroku, Fly, Wrangler), browser profiles and cookies, and
  the macOS keychains with the Security service. The `SSH_AUTH_SOCK` and
  `GNUPGHOME` targets are denied wherever they point.
- Writes to persistence locations: shell startup files, `~/.ssh`,
  `~/.gitconfig` and `~/.config/git`, `~/.cargo/bin`, `~/.cargo/config*`,
  `~/.local/bin`, launch agent and daemon directories, systemd and autostart
  units, and `.git/hooks` in any repository except cargo's own git cache.

A refused access fails the build script, and a build script that needs a
path or variable `strict` or `offline` withholds gets it through a grant:

```toml
[[isolation.grant]]
crate = "openssl-sys"
read = ["/opt/homebrew/opt/openssl"]
write = []
exec = []
env = ["OPENSSL_DIR"]
```

A grant applies at `strict` and `offline` only when the crate is in the
build's `Cargo.lock`; paths must be absolute. `protect` is open outside the
denylists and takes no grants.

Every network destination and every denied access is recorded under
`<local data dir>/stow/audit`: `network-audit.<date>.jsonl` files from the proxy and
`denied-access.<date>.jsonl` with one JSON line per denial. `audit_files`
(default 30) is the number of daily files kept of each. Denied accesses are
recorded on macOS and Linux; Windows reports none.

`protect` is enforced on macOS and Linux through heel's credential and
persistence denylists. On Linux it, like `strict` and `offline`, needs kernel
6.7 or newer, and the denylists also need `kernel.yama.ptrace_scope` of 1 or
lower; a host that fails either makes the command fail with an error naming
the isolation level and the cause, never a build with less protection. On
Windows heel refuses the denylists, so `protect` fails when the sandbox is
created; `strict`, `offline` and `off` work there, and `strict` is the
default on Windows (it reads and writes only the granted paths, so
credentials are unreachable). An explicit `protect` on Windows still fails and
is never replaced by `strict`. No level falls back to
another. A sandbox that cannot be set up fails the command.

## `stow predict`

Read-only cache-coverage analysis. It posts nothing and enqueues nothing:
the dependency graph never leaves the machine, and the command is safe to
run in a loop or a script.

Prints two numbers:

- **index has rows for X / Y transitive dependencies** — an upper bound
  reflecting what the signed index slice covers. Whether each row is
  *usable* at runtime depends on the user's exact
  `dependency_c_metadata_json` resolution matching the cached entry's.
- **direct deps with cached artifacts M / N** — the direct registry
  dependencies whose resolved version has a cached artifact in the index.
  Coverage short of 100% is served per unit — every covered unit is
  injected and the rest compile — so this line reports the direct-dep
  slice of what the cache can serve.

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

Setup ends by **fetching the index slice** for the host target and the
rustc of the toolchain it ran under, through the same signed-slice fetch
`stow build` uses, and leaves it verified in the local cache. The wrapper
that plain `cargo` runs reads slices from the cache only — it never
touches the network — so without this fetch a fresh install's first
plain `cargo build` would serve no public-cache unit. A failed fetch
fails setup with the registry's error; nothing falls back. A registry
that has no slice for the toolchain yet is not a failure: the slice is
then empty. The fetched slice is a snapshot: the wrapper never refreshes it, so
`stow index refresh` (or a `stow check`/`build`/`test`, which refresh it
themselves) brings in newer public units.

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

Run outside GitHub Actions, the mutating commands — `scheduler reset`,
`scheduler demand-feed`, `queue retry|cancel|promote|purge`,
`dispatch-freeze engage|clear`, `dispatch-cap set`, `submit`,
`maintenance`, `watchdog`
(not `--dry-run`), and the `preheat` lanes under `--yes` — do not call
the edge or Cloudflare themselves: they dispatch
`.github/workflows/operations.yml` on `main` with the `stow-admin login`
token, print the run URL, follow the run and succeed only when it does.
The run is the record of who changed what; the edge's mutating routes
accept nothing else. See [`DEPLOYMENT.md`](DEPLOYMENT.md#operator-mutations).

- `stow-admin status` — lane depths, dependents blocked behind failed
  dependencies, oldest pending age, in-flight builds with their GitHub
  Actions run URLs, and per-target outcomes over the trailing 24 h.
  `--watch` repaints a live view of the scheduler queue merged with
  `build-crate.yml`'s in-flight runs every 30 s until Ctrl-C; under
  `--json` each frame is one NDJSON line per tick.
- `stow-admin queue list [--status failed] [--target T] [--rustc V] [--crate X] [--older-than 24h]`
  — filtered queue rows; `queue retry|cancel|promote|purge`
  mutate the same selection (explicit `--task-id`s or filter flags),
  printing the matched rows first and applying only under `--yes`.
  `purge` also requires `--older-than` so live work can never be
  swept. `retry` returns `failed` rows — builds that exhausted their
  automatic retries or were operator-cancelled — to `pending` with a
  fresh `attempt`, e.g. `--status failed --rustc V --target T`.
- `stow-admin coverage <crate>[@version] [--target T]` — which servable
  identities exist per CI target, and which targets have none.
- `stow-admin runs failures --since 24h` — classify the failed tasks of
  `build-crate.yml` runs from their job logs, grouped by failure class.
- `stow-admin artifacts inspect <c_metadata> --target T --rustc-version V`
  — the catalog row plus its OCI bundle manifest;
  `artifacts prune --rustc-version V --yes` deletes a retired toolchain's
  catalog rows (GHCR tags are not deleted).
- `stow-admin cache stats` / `cache clear --prefix <p> --yes` — the
  repository's GitHub Actions cache quota and prefix eviction.
- `stow-admin maintenance ensure|on|off|status [--scope anonymous|lanes|all] [--yes]`
  — the zone WAF maintenance rules; `ensure` creates the entrypoint and
  any missing rule disabled (`ensure`/`on`/`off` are mutations). Every
  invocation, `status` included, runs in `operations.yml`, which holds
  the Cloudflare token.
- `stow-admin dispatch-cap status` — the dispatch caps in force
  (in-flight `build-crate.yml` runs overall and on macOS runners) and
  where each comes from: the deploy bindings or the operator setting.
  `stow-admin dispatch-cap set --jobs N [--macos M]` replaces the
  `STOW_MAX_CONCURRENT_JOBS` / `STOW_MAX_CONCURRENT_MACOS_JOBS` binding
  values at claim time until the next `set` — there is no clear and no
  expiry, `--macos` omitted leaves that cap on its binding, `--jobs 0`
  pauses dispatch, and no ceiling is checked. A lowered cap cancels
  nothing in flight: new claims pause until the in-flight count drops
  below it.
- `stow-admin submit --crate-name X --version 1.2.3 --features-json '["default"]' --target aarch64-apple-darwin --rustc-version 1.91.1 --yes`
  — enqueue one specific build task.
- `stow-admin preheat binary <crate>[@version] [--targets a,b] [--rustc-version ...] --yes`
  — preheat one named **binary** crate's dependency graph from
  crates.io: stow-admin fetches the `.crate` tarball and runs cargo's
  resolver in-process once per CI target — every crates.io node an
  ordinary crate task at its resolved feature set, with its crates.io
  dependencies as `depends_on` edges. The binary's own package is a name
  source, never a task. The published tarball's bundled `Cargo.lock` is
  dropped before the resolve like every other lane's — the resolve
  lands on the latest semver-compatible versions, its pins surviving
  only as yanked/git admission. `preserve_lockfile` stays `false` on
  every derived task — on the runner it names the task crate's own
  lockfile, not the source binary's. A crate with no binary target is
  refused. `--rustc-version` defaults to the scheduler's current
  stable channel version, `--targets` to every CI target.
- `stow-admin preheat top-binaries --rustc-version ... [--targets a,b] [--limit 100] --yes`
  — the popularity lane (stow#891): the top-N crates whose *default*
  version ships a binary target and no library (stow#918), ranked by
  the last 90 days of `version_downloads`. Both answers come from one
  fetch of the crates.io daily database dump (`default_versions` →
  `versions.bin_names`/`has_lib` for the binary check); no categories
  and no per-crate API calls. Each candidate resolves exactly the way
  `preheat binary` resolves one: name sources, never tasks of their
  own. The emitted tasks carry the crate's 90-day download count as
  their queue priority. A binary that fails to resolve is reported and
  skipped; `--targets` defaults to every CI target.
- `stow-admin preheat missed --rustc-version ... [--limit 50] [--since-days 7] [--targets a,b] --yes`
  — promote the top-K most-missed `(crate, version, features)` identities
  from the `stow_cache_misses` Analytics Engine dataset.
- `stow-admin preheat projects submit [--file preheat/projects.toml] --rustc-version ... [--targets a,b] [--source-trees preheat/source-trees.toml] --yes`
  — resolve every repository the reviewed `preheat/projects.toml` lists:
  stow-admin does a depth-1 git fetch of the repository and materializes
  its pinned submodules recursively, drops the committed
  `Cargo.lock` so cargo re-resolves the latest semver-compatible
  versions, and runs the resolve once per CI target — in-process, four
  projects at a time (`resolve::RESOLVE_CONCURRENCY`; cargo's
  `GlobalContext` is not `Sync`, so each worker thread builds its own).
  Every crates.io node in
  the resolve is enqueued as an ordinary crate task at its resolved
  feature set — feature sets are never merged — with its crates.io
  dependencies as `depends_on` edges at the same `(target,
  rustc_version)`. A repository that fails to resolve is reported and
  skipped; a project contributes names and feature sets, never version
  pins. `--source-trees` declares pinned extra source trees for
  projects whose checkout names inputs git does not carry — schema
  and semantics in [source-trees.md](source-trees.md).
- `stow-admin preheat projects generate [--limit 200] [--min-stars 250] [--output preheat/projects.toml]`
  — refresh the reviewed list: every entry already in the file is
  re-evaluated under the same admission rule — a git tree carrying a
  `Cargo.lock` beside a `Cargo.toml`, shallowest first, which is why
  libraries (they commit no lockfile) drop out to the download-ranked
  lane — and stays while it passes, whether the sweep named it or a
  human merged it; a listed entry whose tree fetch fails transport-wise
  stays too, since a network failure says nothing about the repository.
  The star sweep only discovers new candidates, appended after the
  kept entries. Prints every rejection with its reason and writes the
  file; `preheat-projects.yml` runs this weekly and opens the pull
  request.
- `stow-admin preheat plan <crate>[@version] [--target T]` — dry-run the
  closure expansion a request would produce; enqueues nothing.
- `stow-admin preheat manual --crates <file>|--projects <file>
  --rustc-version <v> [--targets a,b] [--priority 30]
  [--source-trees <file>] [--yes]` — the
  operator-driven wave (stow#880): resolve the input in-process and
  submit one dependency tree per source to the scheduler's operations
  lane at `--priority` — the same operand `stow-admin submit` takes.
  The scheduler owns dispatch from there; without `--yes` the plan
  prints and nothing is submitted. Resumable — the scheduler merges on
  task identity, so a re-run inserts only what is still missing.
  A `--projects` repository that fails to
  resolve is reported after the wave submits the rest, exiting
  non-zero naming it; a `--crates` or `--dirs` failure still aborts
  before submission. `--source-trees` is only
  valid with `--projects` — see [source-trees.md](source-trees.md).
  Under `--yes` the command runs in `operations.yml`, which receives the
  `--crates`, `--projects` and `--source-trees` files' contents;
  `--dirs` resolves directories on the operator's machine and is
  refused there — submit the same crates with `--crates` or
  `--projects`.
- `stow-admin index export --out-dir <dir>` /
  `index publish --file <index> --folded <folded>` /
  `index report --file <index>` / `index reconcile --rustc-version <r>` /
  `index targets` — export
  every changed index slice in one pass from the registry's verified
  records artifacts (each `index.<t>.<r>` plus its `folded.<t>.<r>`
  companion; only the records tags no folded set covers are pulled),
  push both to GHCR signed under the index workflow (mock deploys
  delegate to `stow-mock-registry publish-index`), and report each
  slice's membership to the scheduler. `index-publish.yml`
  runs this loop after every `build-crate` run, preceded by `index
  reconcile`, which reports in full every published slice whose
  generation the scheduler does not hold. `index targets` lists
  the `(target, rustc)` pairs a published index covers.

None of this has to be run by hand. `preheat-cron.yml` dispatches the
whole wave — `preheat top-binaries` and
`preheat projects submit` — once per
UTC day and immediately whenever the stable channel moves, since the
cache identity pins the exact stable `rustc_version` and every release
invalidates the pool. Re-submitting the same list is deliberately cheap:
the scheduler deduplicates on task identity, leaves completed tasks
completed, and retires pending tasks the catalog already covers, so each
wave builds only what is missing or previously failed.

`stow-admin` requires `STOW_EDGE_URL` and a GitHub account with push
access to `water-rs/stow`, signed in with `stow-admin login`. A command
that dispatches `operations.yml` also requires the login token to carry
Actions read and write, and refuses a `STOW_EDGE_URL` that is unset or
loopback before dispatching. Reads use the login token directly.
The exceptions never touch the edge: `preheat projects generate`
touches only GitHub, `index export`/`publish`/`targets` touch only
the registry, and a preheat lane (`top-binaries`, `binary`,
`missed`, `projects submit`, `plan`) run without `--yes` only plans and
needs no edge. See [`ENVIRONMENT.md`](ENVIRONMENT.md).

## Local code signing (macOS)

Every link leaves a fresh ad-hoc signature on `stow-admin`, and a
keychain item's ACL evaluates the calling program against the code
requirement it recorded — a new cdhash is a new program, so an "Always
Allow" on the login item survives only until the next `cargo build`.
Signing every local build with one stable identity makes the
requirement certificate-based instead, and one "Always Allow" holds
across rebuilds.

Two committed pieces, both opt-in:

- `admin/build.rs` emits
  `cargo:rustc-link-arg-bin=stow-admin=--ld-path=<repo>/scripts/signing-ld.sh`
  when `STOW_LOCAL_SIGNING_IDENTITY` is set on a macOS target, selecting
  the script as the linker for the `stow-admin` binary alone — nothing
  else's rustc command line changes, so no other unit's cache identity
  moves. The script runs `ld`, then `codesign --sign` on the output —
  only the `stow-admin` binary is signed, including the
  `CARGO_BIN_EXE_stow-admin` the integration tests spawn. Unset, the
  build script emits nothing but its rerun trigger and the link is
  byte-for-byte what it is without the mechanism. Set to an identity
  `codesign` cannot find — or any other codesign failure — the link
  fails with a message; there is no silent unsigned build under a set
  variable.
- `scripts/local-signing-identity.sh` creates that identity once per
  machine: a self-signed EC P-256 certificate (`keyUsage` digital
  signature, `extendedKeyUsage` code signing — what `-p codesigning`
  lookups and `codesign` require) imported into the login keychain with
  `/usr/bin/codesign` authorised, plus the key partition list modern
  macOS checks separately. Idempotent — a second run keeps the existing
  identity and re-applies the partition list. It asks once for the
  login keychain password. The identity need not be trusted: the ACL
  matches the certificate leaf, not a trust decision.

Setup is one pass:

```sh
scripts/local-signing-identity.sh        # creates stow-admin-local
# then make the variable reach cargo, either per shell
export STOW_LOCAL_SIGNING_IDENTITY=stow-admin-local
# or once, in ~/.cargo/config.toml:
#   [env]
#   STOW_LOCAL_SIGNING_IDENTITY = "stow-admin-local"
```

Setting the variable re-links `stow-admin` once (the build script's
`rerun-if-env-changed` fires, and the new `--ld-path` flag changes that
one unit's command line); afterwards the mechanism costs one `codesign`
call per `stow-admin` link. Unset the variable to return to unsigned
ad-hoc links. Linux and Windows are untouched — their credential stores
do not bind access to the caller's signature, and the build script
gates on `CARGO_CFG_TARGET_OS`.