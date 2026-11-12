# stow

A prebuilt cache for Rust dependencies, and a local compilation cache that
replaces sccache. `cargo build` asks stow for each dependency: if a
signed prebuilt exists — on your machine or in the public cache — it is
dropped into `target/` and rustc never runs; otherwise rustc compiles it
and stow keeps cacheable outputs for later builds on the machine.

The public cache is built on GitHub Actions in public, signed by the
workflow that built it, and served through
[stow.waterui.dev](https://stow.waterui.dev), where anyone can also
request a crate.

## Install

```sh
curl -fsSL https://stow.waterui.dev/install.sh | sh      # macOS, Linux
```

```powershell
irm https://stow.waterui.dev/install.ps1 | iex           # Windows
```

The installer puts `stow` on your `PATH` and runs `stow setup`, which wires
`$CARGO_HOME/config.toml` so every `cargo` invocation on the machine goes
through stow's rustc and C/C++ wrappers. On Linux it also installs mold
and selects it as the linker. Nothing per project.

Then build as usual:

```sh
cargo build
```

A plain `cargo build` is a session of the per-user stow daemon: each rustc and
C/C++ wrapper asks the daemon what to do with its unit, runs the compiler when
told to, and exits as soon as the compiler does; the lookups, the stores and
the bookkeeping happen in the daemon. The wrapper starts the daemon when it is
not running. A build whose sandbox cannot reach the daemon's socket, or start
the daemon, fails and says so: no wrapper decides anything on its own, so
there is no fallback that builds without stow. On Windows the daemon is started
by a scheduled task that `stow setup` registers once (the installer runs it);
without that task a build fails naming `stow setup`. See
[Sandboxes](docs/USAGE.md#sandboxes).

Without `stow setup`, `stow check`, `stow build` and `stow test` are
drop-in replacements for the cargo subcommands. `stow update` updates the
install. In GitHub Actions, `- uses: water-rs/stow@main` does the same
for the job. Every command and flag is in [docs/USAGE.md](docs/USAGE.md).

## What you get

**Prebuilt dependencies.** Each dependency unit is looked up in a signed
index of the public cache that stow keeps on your machine; your dependency
graph is resolved locally and is never sent anywhere for a lookup. A hit
is downloaded, checked against the digest the index pins and the
signature of the workflow that built it, and placed in `target/`.

**A shared local cache.** Bundles stow downloads and cacheable
dependencies it compiles are kept in one cache
under `~/.stow`, shared by every project and worktree on the machine. A
second project using the same crate, a `cargo clean`, a new worktree or a
branch switch hits it without the network. Hits are placed in `target/`
as copy-on-write clones on APFS, Btrfs, reflink-enabled XFS and ReFS Dev Drive, so ten projects
sharing a crate store its bytes once; on ext4 or NTFS they are plain
copies. sccache, by comparison, expands every hit into a fresh copy per
project.

The local cache stores crates.io and git dependencies. Workspace and path
crates compile locally. The remote, local crates.io and local git layers
can each be disabled; see [Cache layers](docs/USAGE.md#cache-layers).

**It works offline.** With the network, GHCR or stow.waterui.dev down, a
build serves what the local cache holds and stores what it compiles; the
missing pieces compile locally. Cargo still needs the dependency sources
and toolchain to be available on the machine.

**The cache fills itself.** A dependency your build had to compile is
reported to the scheduler (with a small proof-of-work), and the public
cache builds it. The report carries the identities of the crates your
build compiled; the rest of your graph stays on the machine.

## What is in the public cache

Compiled library and proc-macro crates — rlibs, dylibs and proc-macros —
and their reusable build-script executables. Project binaries and your
own workspace code are not published.

A cached build-script executable still runs when Cargo needs its output;
stow skips compiling the script, not executing it. Scripts and proc macros
that embed their source directory through `CARGO_MANIFEST_DIR` compile
locally, with that directory included in their local cache key.

A crate is cached at one exact identity: crate, version, feature set,
target, rustc version, profile, host or target side, and the identities
of its own dependencies. The same crate at two feature sets is two artifacts. A build that needs a
feature set contained in a larger built set is served the larger set,
and the exact set is queued so the next build hits exactly.

The cache builds the latest release of each semver-compatible line. If
your lockfile pins an older patch release, that crate is a miss until
you update; `stow predict` lists the compatible upgrades that would hit,
and `--silent-compatible-upgrades` applies them.

On Linux a crate that links a system library — `openssl-sys`,
`alsa-sys` — is built against the system libraries of the Ubuntu
release the builders run on. If its build script turns the library's
version into compile flags, your machine is served only when its own
library yields the same flags; otherwise the crate compiles locally.

Crates enter the cache from the misses real builds report, from requests
at [stow.waterui.dev](https://stow.waterui.dev), and from preheat waves
over the most-downloaded binary crates and the most-starred Rust
applications, rerun on every stable Rust release. `stow predict` reports
how much of your project is covered.

## On Linux, mold is the linker

The cache publishes only the mold variant of units that link
(proc-macro, dylib, cdylib), so mold is required. `stow setup` installs a
pinned, checksummed mold release under stow's own tools directory — no
root, no `PATH` edit — and selects it for every Linux target. `stow
build` without setup does the same for that invocation only. A Linux
build that cannot link with mold stops and says so rather than building
artifacts the cache will never serve. Linker options do not affect rlibs,
so the rest of the graph still resolves.

## Why you can trust it

- Artifacts are built only by `build-crate.yml` on the `main` branch of
  this repository, on GitHub-hosted runners, in public. Third-party build
  scripts run in a sandboxed job that holds no credentials; a separate job
  re-checks the output and signs it.
- Every artifact and every index slice carries a keyless Sigstore
  signature bound to that workflow. stow checks the signature, its Rekor
  entry and the bytes' digest before anything reaches `target/`; a
  failure is a local compile, never a served artifact.
- stow.waterui.dev only relays bytes and queues builds. It holds no
  signing identity, so a compromised site can slow you down but cannot
  hand you an artifact stow will accept.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) has the full model.

## Privacy

stow sends anonymous usage statistics: bundle fetches and a once-a-day
count of builds and hits, with no IP address, dependency graph or
lockfile. `STOW_NO_ANALYTICS=1` turns them off. [PRIVACY.md](PRIVACY.md)
lists every field.

## Documentation

- [docs/USAGE.md](docs/USAGE.md) — every command and flag, the local
  cache, GitHub Actions.
- [docs/CONFIG.md](docs/CONFIG.md) — the config file.
- [docs/ENVIRONMENT.md](docs/ENVIRONMENT.md) — every environment variable.
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — common failures.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how stow works.

## License

MIT — see [LICENSE](LICENSE).
