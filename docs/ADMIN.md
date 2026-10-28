# stow-admin

The operations CLI for the stow cache. It talks to the edge's trusted
routes, to GitHub, to GHCR and to Cloudflare. Most of what it does runs
unattended from workflows; this guide is for running it by hand.
[ARCHITECTURE.md](ARCHITECTURE.md) explains the system it operates,
[DEPLOYMENT.md](DEPLOYMENT.md) the deployment procedures, and
[ENVIRONMENT.md](ENVIRONMENT.md#stow-admin) every variable.

## Conventions

- `--json` (global) prints machine-readable JSON instead of a table.
- Every command that changes production prints its plan and exits 0
  without acting unless `--yes` is given. `scheduler reset` refuses
  outright without `--yes`.
- Durations take `30m`, `24h`, `7d`. Target lists are comma-separated and
  default to every CI target (`stow-admin index targets` prints them).
- A preheat lane run without `--yes` only plans and needs neither the
  edge nor a credential.

## Getting the binary

The merge queue builds a toolchain for every commit that lands on `main`
and publishes it, cosign-signed, as
`ghcr.io/water-rs/stow-toolchain:<main commit sha>-<platform>`.
`stow-admin` is in the `linux-x64` and `macos-arm64` toolchains;
`windows-x64` carries only `stow-build` and `stow-cli`. The signature is
made by `toolchain-publish.yml` on a `gh-readonly-queue/main/*` ref — a
ref only GitHub's merge queue can create — and names the commit.

With [`oras`](https://oras.land), [`cosign`](https://docs.sigstore.dev)
and `jq` installed:

```sh
sha=$(git ls-remote https://github.com/water-rs/stow refs/heads/main | cut -f1)
key=macos-arm64        # or linux-x64
repo=ghcr.io/water-rs/stow-toolchain

gh auth token | oras login ghcr.io --username "$(gh api user -q .login)" --password-stdin
digest=$(oras manifest fetch --descriptor "$repo:$sha-$key" | jq -r .digest)
cosign verify "$repo@$digest" \
  --certificate-identity-regexp '^https://github\.com/water-rs/stow/\.github/workflows/toolchain-publish\.yml@refs/heads/gh-readonly-queue/main/.+$' \
  --certificate-github-workflow-sha "$sha" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
oras pull "$repo@$digest" --output stow-toolchain
tar -xzf stow-toolchain/stow-toolchain.tar.gz -C ~/.local/bin stow-admin
```

The `oras login` is needed only while the package is not anonymously
readable; it is a GHCR read and sends nothing to the edge. Do not skip
`cosign verify`: it is what binds the binary to the reviewed commit.
Workflows pull the same artifact through `.github/actions/stow-toolchain`.

Building from source (`cargo build --release -p stow-admin`) works for
development; the binaries production workflows run are the signed ones.

## Credentials

**The edge.** Outside Actions, `stow-admin` authenticates to the edge
only with:

1. `GH_TOKEN` or `GITHUB_TOKEN`, when set — for a job driving a local mock
   edge with its own ephemeral token;
2. otherwise the token `stow-admin login` stored.

It never sends `gh auth token` to the edge: the edge is untrusted, and
that token carries every scope gh was granted. Inside Actions it mints a
fresh OIDC token per call with audience `STOW_OIDC_AUDIENCE`. The edge
accepts a caller whose GitHub account has push access to
`water-rs/stow`. `STOW_EDGE_URL` names the edge for every edge-backed
command; there is no default.

**GitHub.** `runs`, `builds` and `cache` call the GitHub REST API with
`GH_TOKEN`/`GITHUB_TOKEN`, else `gh auth token`. These calls go to GitHub
only.

**Cloudflare.** `maintenance`, `watchdog` and `deploy verdict` need
`CLOUDFLARE_API_TOKEN`; `preheat missed` needs `CF_ANALYTICS_TOKEN`.
Operators normally hold neither: the WAF toggle runs as the
`maintenance.yml` workflow with the repository's secret.

### `stow-admin login`

```sh
stow-admin login            # sign in
stow-admin login --logout   # forget the stored token
```

Runs GitHub's device flow for the `stow-ci` GitHub App: it prints a code
and a URL, you approve in the browser, and the resulting user token
(eight-hour expiry) goes into the OS credential store — the macOS
Keychain, the Linux kernel keyring, or the Windows Credential Manager. It
is never written to a file or the environment. Run it again when the
token expires.

## What changes production

| Command | Effect |
|---|---|
| `submit --yes`, `preheat … --yes`, `request resolve --yes` | Enqueue work in the scheduler |
| `queue retry/cancel/promote/purge --yes` | Change queue rows |
| `scheduler reset --yes` | Drop the scheduler's whole store |
| `dispatch-freeze engage/clear --yes` | Stop or resume dispatch |
| `maintenance ensure/on/off --yes` | Change the zone's WAF rules |
| `watchdog` (without `--dry-run`), `watchdog clear` | Disable or re-enable workflows, toggle the `anonymous` rule, write the incident issue, send mail |
| `index publish`, `index report` | Push and sign index slices; update the scheduler's published mask |
| `builds digest` (without `--dry-run`) | Comment on and open or close the `Daily failed builds` issue |
| `cache clear --yes` | Delete GitHub Actions cache entries |
| `preheat projects generate` | Rewrite `preheat/projects.toml` locally (no remote change) |

Everything else reads.

## Scheduler

### `stow-admin status`

Lane depths, dependents blocked behind failed nodes, the oldest pending
age, in-flight builds with their Actions run URLs, and per-target
outcomes over 24 hours.

- `--watch` — repaint a live view of the queue merged with
  `build-crate.yml`'s in-flight runs every 30 s until Ctrl-C; under
  `--json` each frame is one NDJSON line.

Needs `STOW_EDGE_URL` and an edge credential.

### `stow-admin queue`

`list`, `retry`, `cancel`, `promote` and `purge` share one selector:

| Flag | Meaning |
|---|---|
| `--task-id <id>` | Act on exactly these task ids (repeatable); the filters below are then ignored |
| `--status <status>` | Lifecycle status |
| `--target <triple>` | Target |
| `--rustc <version>` | Rustc version |
| `--crate <name>` | Crate name |
| `--older-than <duration>` | Last transition at least this long ago |

- `queue list [--limit N]` — matching rows, newest transition first; the
  server caps a page at 500.
- `queue retry --yes` — `failed` rows back to `pending` with a fresh
  attempt cycle and no backoff; the release after a builder fix.
- `queue cancel --yes` — `pending`/`dispatched` rows to `failed` as
  "cancelled by operator".
- `queue promote --yes` — pending rows into the website class: website
  priority (or their own, if higher), exempt from the dispatch floor.
- `queue purge --yes` — delete `completed`/`failed` rows. Needs
  `--older-than` or explicit `--task-id`s, so live work cannot be swept.

Each mutation prints the matched rows first.

### `stow-admin submit`

Enqueue one node at operations priority.

| Flag | Default | Meaning |
|---|---|---|
| `--crate-name` | required | Crate |
| `--version` | required | Version |
| `--features-json` | required | Canonical feature list, e.g. `'["default"]'` |
| `--target` | required | Target triple |
| `--rustc-version` | required | Rustc |
| `--downloads` | `0` | Demand signal carried on the node |
| `--preserve-lockfile` | `false` | Keep the crate's bundled `Cargo.lock`; no lane sets it |
| `--priority` | `30` | Priority as a multiple of a CLI miss's; 30 is the website class |
| `--yes` | | Submit |

### `stow-admin scheduler`

- `scheduler reset --yes` — drop every table, index and trigger in the
  scheduler's store and re-create `schema.sql`. The queue and the
  published mask are destroyed and refill from the lanes that feed them;
  the next index publish's report rebuilds the mask. This is how a schema
  change is applied and how a fresh deployment gets its schema. Freeze
  dispatch first.
- `scheduler demand-feed [--hour YYYY-MM-DDTHH]` — the hourly demand
  feed. Without `--hour` it resumes the durable cursor (an unfinished
  hour re-materializes or redelivers its frozen pages) and then
  materializes the next closed hour from the `stow_cache_misses` dataset.
  `--hour` names one closed UTC hour — the recovery path; when the cursor
  holds an unfinished hour, `--hour` must name that hour.
  `demand-feed.yml` runs it hourly.
- `scheduler budget [--queue-rows N] [--no-seed] [--dispatch-limit N]` —
  the cost probe: drives every scheduler route and the alarm on a seeded
  fixture and reports the rows the Durable Object bills. Answers only on
  mock deploys (`STOW_SCHEDULER_BUDGET=1`).

### `stow-admin dispatch-freeze status|engage|clear [--yes]`

- `status` — whether dispatch is frozen, what tripped it, whether the
  alert went out, and the transition log.
- `engage --yes` — freeze by hand, as a failure-rate or cost trip does.
- `clear --yes` — lift the freeze and resume dispatch of everything that
  queued meanwhile. The only recovery from a trip.

## Coverage and artifacts

Both read the signed index slices in GHCR, verified the way the CLI
verifies them; neither touches the edge.

- `coverage <crate>[@version] [--target T] [--rustc R]` — servable
  identities of one crate per CI target, and the targets with none.
  `--rustc` defaults to the current stable.
- `artifacts inspect <c_metadata> --target T --rustc R` — the index row
  for one artifact.

## Preheat

Every lane resolves in-process with `stow-resolver`, per target, and
submits one dependency tree per source to the scheduler. Re-running a
lane is safe: the scheduler merges by task id and builds only what is
missing.

| Command | Flags | Source |
|---|---|---|
| `preheat binary <crate>[@version]` | `--targets`, `--rustc-version` (default: current stable), `--yes` | One crates.io binary crate, as a name source |
| `preheat top-binaries` | `--rustc-version` (required), `--targets`, `--limit` (100), `--yes` | The top crates by 90-day downloads whose default version ships a binary and no library, read from the crates.io database dump |
| `preheat missed` | `--rustc-version` (required), `--targets`, `--limit` (50 per target), `--since-days` (7), `--yes` | The most-missed identities in `stow_cache_misses` |
| `preheat projects submit` | `--file` (`preheat/projects.toml`), `--rustc-version` (required), `--targets`, `--source-trees`, `--limit`, `--yes` | Every repository in the reviewed list |
| `preheat manual` | `--crates <file>` \| `--projects <file>` \| `--dirs <a,b>`, `--source-trees` (with `--projects`), `--rustc-version` (required), `--targets`, `--priority` (30), `--yes` | An operator wave at operations priority |
| `preheat plan <crate>[@version]` | `--features-json`, `--target`, `--rustc-version` | Dry run: the tasks one request would enqueue. Enqueues nothing |

- A binary crate is a name source, never a task: its bundled lockfile is
  dropped, cargo resolves the latest semver-compatible versions, and its
  crates.io nodes are submitted with their dependency edges. A crate
  with no binary target is refused.
- `preheat projects submit` fetches each repository at depth 1 with its
  submodules, drops the committed `Cargo.lock`, and resolves. A
  repository that fails is reported and skipped. `--source-trees`
  declares pinned extra source trees for checkouts that need inputs git
  does not carry ([source-trees.md](source-trees.md)). `--limit` resolves
  only the first N repositories.
- `preheat manual --crates` takes one `name` or `name@version` per line;
  `--projects` takes a file in the `projects.toml` shape; `--dirs` takes
  local project directories. A failing `--projects` repository is
  reported after the rest submits and the command exits non-zero; a
  `--crates` or `--dirs` failure aborts before anything is submitted.
- `preheat projects generate [--limit 200] [--min-stars 250] [--output preheat/projects.toml]`
  refreshes the list: every listed entry is re-checked against the
  admission rule (a git tree carrying a `Cargo.lock` beside a
  `Cargo.toml`) and kept while it passes; GitHub's most-starred Rust
  repositories only add new candidates. It prints every rejection and
  writes the file. `preheat-projects.yml` runs it weekly and opens the
  pull request; the wave reads only the merged file.
- `preheat cost ledger|report|production` — the mock-only `Preheat cost`
  test's pieces (`scripts/preheat-cost.sh`).

`STOW_RESOLVE_CARGO_HOME` and `STOW_RESOLVE_CONCURRENCY` (default 4)
control where and how wide resolution runs. Nothing here needs to be run
by hand in normal operation: a new stable rustc and the daily
`preheat-cron.yml` tick both run `preheat-admin.yml`.

## Index

- `index export --out-dir <dir> --rustc-version <v> [--full]` — fold the
  registry's signed records of one rustc into every `(target, rustc)`
  slice. Pulls each published `index`/`folded` pair, then only the
  `records-<rustc>-*` artifacts no folded set covers, verifying every
  signature against `build-crate.yml@main`; writes the changed slices,
  their folded sets, `slices.json` and `new-records.json`. `--full`
  ignores the folded sets and re-reads every record — the first publish
  of a rustc, an index format change, and recovery.
- `index publish --file <index> --folded <folded>` — push a slice and its
  folded companion and sign both. Needs `GHCR_USERNAME`/`GHCR_TOKEN` and
  `cosign`, and the signature is accepted by the CLI only from
  `index-publish.yml` on `main`; run by hand it is for mock registries
  (`STOW_MOCK_PRIVATE_KEY_PATH`).
- `index report --file <index>... [--full]` — report a publish run's
  slices to the scheduler in one call. A delta by default; `--full` sends
  the whole membership, and a refused delta is resent once as full.
- `index targets` — print `CI_TARGET_TRIPLES`.
- `index join --rustc-version <v>...` — resolve the usage statistics'
  bundle digests to crate identities through the signed slices.

`index-publish.yml` runs export, publish and report after every
`build-crate` run.

## Website requests

- `request resolve --request <json> [--cargo-home <dir>] [--yes]` — the
  `resolve-request.yml` job: resolve one admitted request on every CI
  target, prune against the published slices, enforce the closure cap,
  and with `--yes` post the outcome to the scheduler.

## Build runs

- `runs failures --since <duration>` — failed `build-crate.yml` tasks in
  the window, classified from their job logs and grouped by failure
  class.
- `builds digest [--since RFC3339] [--until RFC3339] [--dry-run]` — the
  daily digest: the window's failed builds (default the 24 hours before
  `--until`, default now), classified by the step each died in, posted as
  one comment on the open `Daily failed builds` issue, which a clean day
  closes. `build-failure-digest.yml` runs it daily.
- `cache stats` — the repository's Actions cache usage against its
  10 GiB quota. `cache clear --prefix <p> --yes` deletes every entry
  whose key starts with `<p>`.

## Incidents

### `stow-admin maintenance ensure|on|off|status [--scope anonymous|lanes|all] [--yes]`

The zone's WAF maintenance rules, which block traffic before the Worker
runs:

| Scope | Blocks |
|---|---|
| `anonymous` | everything on the edge host except the admin, scheduler and webhook routes |
| `lanes` | the public routes that reach the scheduler; bundle bytes keep serving |
| `all` | the whole hostname |

`ensure` creates the ruleset entry point and any missing rule, disabled;
`deploy-edge.yml` runs it on every deploy. `on`/`off` flip one rule.
`status` reads all three. Needs `CLOUDFLARE_API_TOKEN` (Zone WAF Edit)
and `CF_ZONE_ID`, and `STOW_EDGE_URL` for the hostname the rules match.

Operators toggle through the `maintenance.yml` workflow (`action`:
`status`/`on`/`off`, `scope`), which runs this command from the signed
toolchain with the repository's Cloudflare secret. Dispatching it needs
write access to the repository, so every toggle is an Actions run under
a GitHub account.

### `stow-admin watchdog [--dry-run]` and `watchdog clear`

`watchdog.yml` runs it every 15 minutes. It reads Cloudflare usage
against each product's hourly share of the monthly allowance, edge
health, the build pipeline and the public endpoints. On a cost,
resource or failure-rate breach it disables `build-crate.yml` and the
preheat and index-publish-cron workflows, enables the `anonymous` rule,
opens or updates the `incident` issue and sends the alert mail. Health
and latency breaches alert without tripping. `--dry-run` prints the
evaluation and the actions without taking them.

`watchdog clear` is the recovery: rule off, the workflows the trip
disabled re-enabled, incident closed, clear mail sent. The watchdog never
un-trips on its own.

Needs `STOW_EDGE_URL`, `CLOUDFLARE_API_TOKEN`, `CF_ACCOUNT_ID`,
`CF_ZONE_ID` and a `GITHUB_TOKEN` that can disable workflows and write
issues.

## Deploy and cost tooling

These back `deploy-edge.yml` and the release gate; they are rarely run
by hand.

- `deploy verdict --phase canary|promoted --account-tag --script
  --baseline-version --candidate-version --baseline-from --baseline-to
  --candidate-from --candidate-to [--min-requests-per-version N]` —
  compare a deploy window's Worker and Durable Object metrics with the
  baseline window and print promote or rollback. Needs
  `CLOUDFLARE_API_TOKEN`.
- `launch-model export [--out launch-model.toml] [--end YYYY-MM-DD]
  [--window-days 7] [--from-snapshot <file>] [--write-snapshot <file>]` —
  regenerate the launch traffic model from production analytics.
- `traffic-cost cpu|peak|verdict|project|fixture-runs` — the pieces of
  `scripts/traffic-cost.sh`: Worker CPU per lane, the peak drive, the row
  budget verdict, the monthly projection, and the fixture's in-flight
  runs. Run the script, not the pieces.
