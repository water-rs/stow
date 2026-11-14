# Administration

`stow-admin` is the operations CLI for cache operators. Not for end users. Nouns then verbs;
`--json` is a global flag (machine-readable stdout instead of the human
table). Commands that take `--yes` require it before applying their plan;
`watchdog clear` is an explicit recovery command.

Run outside GitHub Actions, the mutating commands — `scheduler reset`,
`scheduler demand-feed`, `queue retry|cancel|promote|purge`,
`dispatch-freeze engage|clear`, `dispatch-cap set`, `release-priority set`,
`memory-line set`, `submit`,
`maintenance`, `watchdog`
(not `--dry-run`), and the `preheat` lanes under `--yes` — do not call
the edge or Cloudflare themselves: they dispatch
`.github/workflows/operations.yml` on the edge's release tag with the `stow-admin login`
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
- `stow-admin artifacts inspect <c_metadata> --target T --rustc V`
  — the artifact row read from the verified signed index slice.
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
- `stow-admin release-priority status` — the multiplier release-profile
  library builds rank under (percent of the entry point's priority) and
  whether it is the default (`10`) or the operator setting.
  `stow-admin release-priority set --percent N` replaces it until the
  next `set` — there is no clear and no expiry, no ceiling is checked,
  and the new value re-ranks queued release nodes at the next claim.
- `stow-admin memory-line status` — the scheduler graph's memory lines
  in force (normal line, small line and small increment, in resident
  bytes) and whether they are the deploy bindings
  (`STOW_SCHEDULER_MEMORY_LINE`, `STOW_SCHEDULER_SMALL_MEMORY_LINE`,
  `STOW_SCHEDULER_SMALL_INCREMENT_BYTES`) or the operator setting.
  `stow-admin memory-line set --normal N --small N --small-increment N --yes`
  replaces all three until the next `set` — there is no clear and no
  expiry, and no bound is checked. The setting is stored outside the
  graph, so both commands work while the graph is too large to wake:
  raising `--small` above the graph's size is how it wakes again
  (`stow-admin scheduler reset --yes` is the other way, and drops the
  queue and the backlog). Admission and the wake apply the new lines
  from the next request on.
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
  generation the scheduler does not hold (a full membership over one
  request body posts in parts; a delta too large for one part is
  reported as the slice's full membership). Under `full` the reconcile runs after the
  publish step instead, once every slice it reads is regenerated. `index targets` prints
  every `CI_TARGET_TRIPLES` entry.
  `index published-rustcs` prints every stable rustc release
  (`static.rust-lang.org/manifests.txt`) whose `stow-cache-v2-<rustc>`
  package holds tags, probed through the registry's anonymous tag
  listing; `operations.yml` reports each one's slices after a
  scheduler reset.

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
touches only GitHub, `index export`/`publish` touch only
the registry, `index targets` prints the compiled target list, and a preheat lane (`top-binaries`, `binary`,
`missed`, `projects submit`, `plan`) run without `--yes` only plans and
needs no edge. See [`ENVIRONMENT.md`](ENVIRONMENT.md).

## Recovery

`stow-admin watchdog --dry-run` evaluates the watchdog without changing
state. After correcting the cause of a trip, `stow-admin watchdog clear`
lifts maintenance rules, re-enables the workflows recorded by the incident,
then lifts the scheduler's dispatch freeze if engaged, and closes the
incident with a recovery email. It is the single recovery step: a workflow
that fails to re-enable keeps the freeze engaged and fails the command. The watchdog never clears
itself. These mutations run through `operations.yml`.

`stow-admin scheduler reset --yes` destroys the scheduler queue and recorded
index membership and recreates its persistence schema. The operations run
then requests published index reports and a fresh preheat wave. Use it for
an explicitly planned schema reset; see [DEPLOYMENT.md](DEPLOYMENT.md).

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
