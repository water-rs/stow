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

```
project      artifacts    cargo     stow    floor     gain
ripgrep             64     11.8      5.7      4.9    2.09x
fd                 115     50.8    208.6      2.1    0.24x
bat                205     32.5     20.5      3.2    1.58x
hyperfine          137     14.4      1.1      1.8   13.18x
tokei              160     19.1      1.4      3.6   13.97x
zoxide              94     15.5      1.3      2.1   11.85x
just               181     27.1     20.2      5.6    1.34x
sd                  80     11.0      6.1      0.9    1.81x
xh                 352     45.9     31.1     12.6    1.47x
dust               115     17.4      4.3      1.9    4.01x
delta              256     42.5     27.1      4.7    1.57x
bottom             212    112.8    117.2      9.1    0.96x
-----------------------------------------------------------
median                     23.1     13.2      3.4    1.70x
```

`eza 0.20.7` is the thirteenth project; its CI capture fails intermittently
(see *dep_scan cannot attribute a shared dependency* below). On a run that
captured cleanly it measures 52.7 s → 46.9 s (1.12x) against an 11.0 s floor.

Excluding `fd` and `bottom`, whose causes are understood and listed below, the
median across the remaining ten is **1.95x**.

## Where it started

Before the fixes in this branch, the same benchmark on the same perfectly
preheated caches produced a **1.02x median** — statistically indistinguishable
from plain cargo on all eleven projects that ran, with a range of 0.96–1.06x.
Forcing the cache path on with `--no-stow-resolver` was *worse*: a 0.91x median,
slower than cargo on seven of eleven.

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

## What is still costing acceleration

Median `stow` is still **3.0x above the floor**. The remaining causes, in
descending measured impact:

### Native artifacts are hex-encoded, duplicated, and uncompressed

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

### The top-crate fast path is all-or-nothing

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

### The C object cache reaches almost nothing

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

### dep_scan cannot attribute a shared dependency

`eza`'s capture fails intermittently with
`dep_scan could not resolve authoritative dependency owner for cfg_if ... while
scanning backtrace`. The build succeeds; the scan cannot decide which unit owns a
shared rmeta. A crate that hits this can never be preheated.

### No coverage reporting

"Served N of M available" is the number that tells a user whether stow is
working, and it is only visible at `debug`. Every defect above was silent at
default verbosity — the 1.02x median looked exactly like a working cache. A
one-line post-build summary would turn a regression like #1 or #3 into a day-one
bug report.
