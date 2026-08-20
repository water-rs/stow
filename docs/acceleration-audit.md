# Acceleration audit: stow across 13 popular Rust projects

Measured on 2026-08-19. rustc 1.94.1, `x86_64-unknown-linux-gnu`, 4 cores,
15 GB RAM, `dev` profile, `CARGO_INCREMENTAL=0`.

## Method

Every project was given an **ideally preheated cache**: the trusted CI builder
(`stow-build`) compiled each checkout from its own `Cargo.lock`
(`preserve_lockfile: true`) with default features on the same rustc, so every
dependency artifact existed and was exactly keyed. Artifacts were signed into a
local `stow-mock-registry` and served by a local stand-in for the edge worker
implementing the routes the CLI calls (`/api/v1/catalog/graph`,
`/api/v1/catalog/resolve-lockfile`, `/api/v1/artifacts/{target}/{rustc}/{c_metadata}`,
`/api/v1/artifacts/batch`, `/api/v1/artifacts/semantic`).

Per project, from a clean target directory:

| column | what it measures |
|---|---|
| `cargo` | `cargo build`, cold |
| `stow` | `stow build`, warm artifact cache (one warm-up run first) |
| `floor` | `cargo build` after `cargo clean -p <each workspace member>`, i.e. every dependency already compiled |

`floor` is the theoretical best any dependency cache can reach: it is what the
build costs when only first-party code needs compiling.

## Result

Every project builds correctly (`rc=0` on every measured run) and none is
slower than plain cargo.

```
project      artifacts    cargo     stow    floor     gain
sd                  80     10.7      2.2      0.9    4.76x
zoxide             112     15.6      3.8      2.2    4.11x
hyperfine          154     14.3      3.8      1.8    3.75x
dust               127     15.6      4.6      1.8    3.39x
just               185     24.1      8.2      5.4    2.96x
tokei              192     18.7      6.4      3.5    2.93x
bat                222     31.2     10.8      2.9    2.88x
delta              277     43.8     15.5      4.8    2.83x
xh                 385     44.0     17.1     12.4    2.57x
eza                190     42.1     17.9     10.4    2.35x
ripgrep             64     11.6      5.3      5.0    2.19x
fd                 115     50.7     29.6      2.1    1.71x
bottom             235    110.5    108.7      7.9    1.02x
-----------------------------------------------------------
median                     24.1      8.2      3.5    2.88x
```

433 s of cargo becomes 234 s, against a 61 s floor. The slowest result is
`bottom` at 1.02x, and that one is correct by construction: it sets
`[profile.dev.package."*"] opt-level`, so its dependency compile identities
can never match the cache, `profile_guard` detects that up front, and stow
runs plain cargo.

What each build actually served is now printed at default verbosity:

```
ripgrep     stow: served 24 of 24 cacheable dependencies
fd          stow: served 62 of 62 cacheable dependencies | C objects: 186 of 186
bat         stow: served 108 of 108 cacheable dependencies | C objects: 244 of 244
hyperfine   stow: served 73 of 73 cacheable dependencies
tokei       stow: served 97 of 97 cacheable dependencies
zoxide      stow: served 65 of 69 cacheable dependencies, 4 errored
just        stow: served 98 of 99 cacheable dependencies, 1 errored | C objects: 6 of 6
sd          stow: served 44 of 45 cacheable dependencies, 1 errored
xh          stow: served 188 of 190 cacheable dependencies, 2 errored | C objects: 78 of 78
eza         stow: served 97 of 105 cacheable dependencies, 8 errored | C objects: 202 of 202
dust        stow: served 64 of 66 cacheable dependencies, 2 errored
delta       stow: served 137 of 137 cacheable dependencies | C objects: 243 of 243
bottom      (passthrough)
```

## Where it started

On the same benchmark and the same perfectly preheated caches, `stow build`
originally produced a **1.02x median** — statistically indistinguishable from
plain cargo on all eleven projects that ran, range 0.96–1.06x. Forcing the
cache path on with `--no-stow-resolver` was worse: a 0.91x median, slower than
cargo on seven of eleven.

An intermediate run looked much better than it was. Four projects reported
4.9x to 14.4x while **failing to compile** — a build that fails exits early and
looks fast, and the harness recorded exit codes without displaying them. Both
causes are fixed and described below, and `report.py` now refuses to print a
gain for any run that did not exit zero.

## What was wrong

### 1. The resolver's empty answer was read as "nothing is cached"

`cargo_cmd::run` returned a plain cargo passthrough whenever the edge resolver
could not synthesize a cache-optimized `Cargo.lock`, reasoning that a resolver
which found nothing means the per-rustc wrapper would miss too.

The resolver answers a different question: *is there a **different** lockfile,
with better cache coverage, that cargo would also accept?* A workspace whose own
lockfile is already fully covered is precisely the case where it has nothing to
improve. The best case was being turned into a plain cargo run.

Fixed by moving the passthrough decision after the graph analysis and gating it
on whether any cached artifact covers this graph. The no-slowdown floor is
preserved: zero coverage, a failed analysis and a missing config all still exec
cargo with no wrapper.

### 2. Producer and consumer disagreed on the profile

`ci/src/capture.rs` stored `parsed.profile()` — the raw `-C` flags — while every
lookup path compares against `normalized_cache_profile()`, which reports
`debuginfo: 1` when rustc was given no `-C debuginfo` *and* for every invocation
that does not emit `link`. The two disagreed by construction on all of cargo's
pipelined `--emit=metadata` units.

A fresh capture of `just 1.36.0` now yields 99 records at `(debuginfo 2, link)`
and 82 at `(debuginfo 1, metadata-only)`, instead of 181 all claiming
`debuginfo 2`.

### 3. The circuit breaker amplified every mismatch into a total outage

It trips after 5 consecutive failures and stays open for 60 s — longer than most
builds — and bundle identity/semantic divergence was recorded as a *failure*. A
handful of legitimately-unmatched units, typically the proc-macro host graph,
tripped it a few invocations in, and every remaining crate in the build bypassed
the cache. On `just` that was **68 trips per build**.

An artifact that arrives intact but does not describe this invocation is a miss,
not an outage. Only transport and materialization failures still count. `just`
went 29.4 s → 18.6 s on this change alone, with trips going 68 → 0.

### 4. `cached_dependency_profile()` asked for a profile nothing is built with

It hardcoded `debuginfo: 1`, but trusted CI builds under cargo's default dev
profile (`debug = true` → `debuginfo: 2`) — the same profile `profile_guard.rs`
enforces on the client. Every top-crate cached-deps lookup missed by
construction; on ripgrep the fast path died on its first direct dependency.

### 5. Tracing wrote to stdout in all four binaries

`stow-cli` and `stow-build` also serve as `RUSTC_WRAPPER`, and cargo hashes the
stdout of `rustc -vV` *run through the wrapper* into every unit's `-C metadata`.
One log line changes the cache key of every crate in the build — and changes it
again next invocation, because the line carries a timestamp.

On this branch the wrapper's tracing was already gated off unless
`STOW_TRACE_WRAPPED_COMPILERS` is set, so the damage was confined to anyone
debugging stow — which is exactly when it is least affordable. Every subscriber
now writes to stderr, with an integration test asserting the wrapper's stdout is
byte-identical to plain rustc's across every `RUST_LOG` × trace-flag combination.

### 6. The prefetch pre-pass loaded every bundle to ask a yes/no question

`warm_exact_artifacts` called `load_cached_bundle` per artifact — a file lock, an
LRU `UPDATE` and five `SELECT`s each, serially — only to `drop` the result. On a
warm cache that cost ~90 ms per artifact: over 10 s for a 115-crate graph, twice
per build, before a single rustc ran. Replaced with one indexed query plus one
batched LRU update; the same phase now takes 2–5 ms.

### 7. Workspace inheritance did not parse

`version.workspace = true` in `[package]` is a table, not a string, and
`PackageSection::version` was `Option<String>`. Every manifest using workspace
inheritance — stable since Rust 1.64 — failed to parse and aborted the command.
`sd 1.0.0` died with `invalid type: map, expected a string` before compiling
anything.

### 8. OCI repository segments were not lowercased

`oci_reference()` interpolated the crate name verbatim; OCI repository path
segments must be lowercase and crate names need not be (`Inflector`, `RustyXML`).

### 9. The workspace only built next to unpublished sibling checkouts

`zenwave`, `skyzen`, `skyzen-cloudflare` and `skyzen-services` were `path`
dependencies on directories outside the repository. Now pinned to the published
releases (zenwave 0.5, skyzen 0.1.1, skyzen-cloudflare 0.1, skyzen-services 0.1).
No source changes were needed.

### 10. One crate version's artifact could be served for another

`package_index` keyed packages by library target name alone. A graph can
legitimately hold two versions of one crate — bitflags 1.3.2 alongside 2.5.0 —
and they share the name, so one silently overwrote the other and captures were
attributed to whichever landed last. All four of dust's bitflags records
claimed 2.5.0 while two held 1.3.2's bytes; the client then injected 2.5.0's
rlib into the 1.3.2 unit and the build failed with 126 conflicting-impl errors
inside `nix`.

Captures now record the version read from the invocation's source path,
packages are indexed by name *and* version, and a capture that cannot name its
version is skipped rather than guessed at. Serving an exact bundle also
validates `crate_version` now: the lookup is keyed on `c_metadata`, which is
*supposed* to encode the version, but nothing downstream can detect
wrong-version code.

### 11. Hyphenated library targets never matched

cargo reports a library target's name verbatim — `cfg-if`, `ansi-width` —
while rustc's `--crate-name` is always underscored. Indexing by the raw name
meant no capture of such a crate ever matched a package. On eza that lost half
the graph: 54 captures skipped, 48 more artifacts dropped as their dependents
lost an owner, and 91 of 190 artifacts registered.

`cargo metadata` also now runs `--locked`. It runs after the build has written
a lockfile and must report that exact resolution; without it cargo may
re-resolve and report versions rustc never compiled.

### 12. The prebuilt-deps path produced broken builds

It compiles the top crate alone against a closure of cached rlibs, stripping
`[dependencies]` from a mirrored manifest and passing `--extern` plus
`-Ldependency=<prebuilt>`. It broke builds two ways: stripping
`[build-dependencies]` left hyperfine's `build.rs` unable to resolve
`clap_complete`, and keeping them put the same crate in both cargo's `deps`
directory and the prebuilt one, so rustc refused with "multiple candidates for
rlib dependency clap".

Getting it right needs exact control of rustc's search path across the whole
transitive closure. The per-rustc wrapper reaches the same artifacts without
any of it, and on hyperfine it is both correct and faster — 3.8 s against the
prebuilt path's 4.3 s *failure*. The path is now behind
`STOW_ENABLE_PREBUILT_DEPS`, off by default.

### 13. The cache layer could fail the build

A prefetch error propagated out of `prepare_build_cache_plan`, so one HTTP 500
from the edge aborted `stow build` outright — not slower than cargo, broken.
A failed cache-policy write was fatal the same way. Everything before cargo
launches is now allowed to fail and degrade. `cli/tests/never_slower_than_cargo.rs`
drives a fake edge through three failure shapes, each verified to fail against
the previous behaviour.

## What is still costing acceleration

Median `stow` is **2.08x above the floor**. Entries struck through below were
open when this audit was written and have since been fixed; they are kept
because the measurements explain why the numbers moved.

The one structural gap still open is build-script caching. Cargo compiles
*and runs* one build script per package on every clean build and
`is_cacheable()` excludes them, which is most of the remaining floor gap on
C-heavy projects: fd's floor is 2.1 s against a 29.6 s stowed build, nearly
all of it jemalloc's `configure` and `make`. The C compilations inside that
script are cached now (186 of 186 objects served), but the orchestration
around them still runs.

The rest of this section is kept for the measurements:

### ~~Native artifacts are hex-encoded, duplicated, and uncompressed~~ (fixed)

`NativeArtifacts::out_dir_files` is stored as
`OutDirFile { relative_path, #[serde(with = "hex_bytes")] contents }` inline in
`ArtifactBlobConfig`. Three multipliers stack:

1. hex encoding — 2 JSON bytes per content byte;
2. `edge/src/ghcr.rs` writes the same config **twice** per bundle, once embedded
   in `manifest.json`'s `config` field and once as `oci/config.json`;
3. neither copy is compressed — only `files/*` layers get the `+zstd` treatment.

Measured across fd 10.2.0's 115 cached artifacts:

| what | bytes |
|---|---|
| all compiled outputs (OCI layers, zstd) | 136.8 MB |
| all `oci/config.json` blobs | 1333.9 MB |
| `jemalloc-sys` config alone (each of its 2 records) | 666.9 MB |
| `jemalloc-sys` bundle as served | 1272 MB |

~333 MB of real `OUT_DIR` becomes a 1.27 GB download. This is the whole of fd's
0.24x: now that the graph path engages, fd pays that transfer where before it
silently skipped the cache. **Suggested fix:** ship `out_dir_files` as its own
zstd-compressed OCI layer rather than hex inside the signed config, and stop
duplicating the config into `manifest.json`.

### ~~The top-crate fast path is all-or-nothing~~ (path disabled, see 12)

`resolve_cached_dependency_plan` fails the entire plan if any single direct
registry dependency cannot be satisfied, and the whole prebuilt closure is
discarded. Observed on ripgrep (`pcre2`), just (`pulldown-cmark`) and fd
(`clap`, via a missing `heck` in the closure). One C-linked or unpreheated
dependency is enough. **Suggested fix:** materialize the satisfiable subset and
let cargo compile the rest.

### Build scripts are never cached

Cargo compiles *and runs* one per package on every clean build; `is_cacheable()`
excludes them. `NativeArtifacts` do travel in the bundle but are injected during
the library's rustc call — after the script already ran. This is most of the
remaining floor gap on C-heavy projects: fd's floor is 2.1 s against a 50.8 s
plain build.

### ~~The C object cache reaches almost nothing~~ (fixed)

`cli/src/cc.rs` keys on preprocessed source plus a compiler fingerprint, so it is
publishable — but it is machine-local, never served from the edge, and only
reachable through `CMAKE_C_COMPILER_LAUNCHER` / `CMAKE_CXX_COMPILER_LAUNCHER`.
`CC`/`CXX` are deliberately left unset because `stow cc` parses its first
positional as the executable, which the launcher protocol provides and `CC` does
not. That excludes every `cc-rs` crate — the overwhelming majority of C in the
Rust ecosystem. **Suggested fix:** generate three shims (`stow-cc-launcher` for
the CMake vars, `stow-cc`/`stow-cxx` that prepend `${STOW_REAL_CC:-cc}`), and
record the caller's `CC`/`CXX` into `STOW_REAL_CC`/`STOW_REAL_CXX` before
overwriting them.

### Any dev-profile tuning disqualifies the whole workspace

`bottom` sets `[profile.dev.package."*"] opt-level`, so its dependency compile
identities can never match the cache. `profile_guard` detects this up front and
passes through cleanly — 0.96x, exactly the intended no-slowdown floor, and
correct behaviour. It is still a coverage limit: a workspace that tunes its dev
profile at all gets nothing from the cache.

### ~~dep_scan cannot attribute a shared dependency~~ (fixed, see 10 and 11)

`eza`'s capture fails intermittently with
`dep_scan could not resolve authoritative dependency owner for cfg_if ... while
scanning backtrace`. The build succeeds; the scan cannot decide which unit owns a
shared rmeta. A crate that hits this can never be preheated.

### ~~No coverage reporting~~ (fixed)

"Served N of M available" is the number that tells a user whether stow is
working, and it is only visible at `debug`. Every defect above was silent at
default verbosity — the 1.02x median looked exactly like a working cache. A
one-line post-build summary would turn a regression like #1 or #3 into a day-one
bug report.
