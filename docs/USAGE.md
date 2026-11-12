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

## Cache layers

The cache has three layers, and each is switched off on its own. The `[cache]`
table of the config file ([`CONFIG.md`](CONFIG.md)) sets them for every stow
process (`stow build`, the rustc wrapper plain `cargo` runs, `stow stats`); a
flag on `stow check`, `stow build`, `stow test` and `stow predict` turns a layer
off for that run, over the file. A flag only turns a layer off.

| Layer | Config | Flag | Off means |
| --- | --- | --- | --- |
| Remote cache | `remote = false` | `--no-remote-cache` | No request to the edge or the registry, no miss journal and no inexact report, so nothing about the build's graph leaves the machine. Entries downloaded earlier are not served; those units compile locally and are stored as local entries. |
| Local crates.io cache | `local_crates_io = false` | `--no-local-crates-io-cache` | Locally built crates.io units are neither looked up nor stored. |
| Local git cache | `local_git = false` | `--no-local-git-cache` | Locally built git units are neither looked up nor stored. A crates.io unit compiled over a git dependency is then never stored either. |

```sh
stow build --no-local-git-cache        # a git dependency reads files outside its package
stow build --no-remote-cache           # nothing about this build leaves the machine
```

With every layer off nothing is read or written and the C/C++ object cache is
off too. The layers are independent of build isolation: with the cache off,
`stow build` still runs every build script and proc macro at the configured
isolation level (below). `stow stats` reports the compile time local hits saved
in every configuration. Commands that exist to talk to the remote cache
(`stow predict`, `stow index refresh`, `stow check-artifact`,
`stow fetch-artifact`) fail with a message saying the remote cache is off;
`stow setup` skips the index fetch.

## Build isolation

Every cargo-running command confines the build — cargo, rustc, every build
script, proc-macro and linker it spawns — at one of four levels. The level
is independent of the cache layers: it holds with every layer on or off.

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

### What isolation does not guarantee

Isolation is best effort, not an absolute guarantee. Where confinement and
a working build conflict, stow keeps the build working: `protect` is a
denylist over an otherwise open machine, and code a build runs can still
read and write everything the lists do not name.

One weakness is known. The local cache is shared by every project a user
builds, and what it stores for a crate is whatever the build left in the
target directory. A build script or proc macro can therefore alter the
artifact stored for another crate of the same build, and a later build of
any project that needs that crate at the same identity reuses it — at any
isolation level, `off` included. The public cache is not affected: it
holds only artifacts built and signed by stow's CI. `stow clean` removes
every locally stored artifact. This may be closed in a later release.

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

### Sandboxes

Every compile of a plain `cargo build` through the wrappers is answered
by the per-user daemon, which opens a session of that cargo and ends it
when the cargo exits: the wrapper asks, runs the compiler when told to,
reports and exits, and the lookup, the store and the bookkeeping happen in
the daemon after the wrapper has gone. The process running cargo must
therefore be able to connect to `<run dir>/daemon.sock` (the named pipe on
Windows), or to start the daemon, which needs write access to the run
directory.

A build whose sandbox allows neither fails. There is no fallback: a
wrapper never decides anything on its own, so a build that cannot reach the
daemon cannot build through stow's wrappers at all. Cargo's first probe of
the compiler fails, and the error names the endpoint, the run directory and
the daemon's pid and log. The run directory is `STOW_DAEMON_DIR` when it is
set, and the per-user cache directory's `stow/run` otherwise.

The daemon takes what it knows about a plain build from the processes that
connect, so who may connect decides whose cache and target directories it
works in: the endpoint is owner-only (a `0600` socket in a `0700`
directory on Unix, a pipe only the user's SID may open on Windows), and a
sandbox that lets a process reach it gives that process the daemon's
authority over the user's cache and the target directories of its builds.
The output directories a session accepts are derived from the first unit
of the build; they are not a security boundary.

A daemon that restarts while a cargo is building leaves that build without
the session's in-flight state and its record of locally built crates. The
new daemon refuses that cargo's wrappers until it exits, so the build fails
saying the daemon restarted; run it again.

What the daemon logs while it decides a unit, such as a refused request,
reaches the wrapper's stderr at `warn` and above. With
`STOW_TRACE_WRAPPED_COMPILERS` set, `RUST_LOG` selects what else returns.
Everything else is in the daemon's log, `<run dir>/daemon.log`.

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

## Administration

Operator commands and local administrator code signing are documented in
[ADMIN.md](ADMIN.md).
