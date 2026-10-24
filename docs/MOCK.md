# End-to-end mock recipe

For local development you can run the entire pipeline against three
local processes — no Cloudflare account, no GitHub Actions, no real
GHCR — by chaining `stow-mock-registry`, a Wrangler dev edge, and the
`stow-build` local-CI dispatch endpoint.

## One-command run

`scripts/mock-e2e.sh` is the canonical way to run this recipe. It does
the whole thing unattended — builds the binaries, generates the P-256
key pair, starts all three services, submits one `itoa` task through
`stow-admin`, waits out the scheduler, exports and publishes the signed
index slice, refreshes it into the CLI's local index, and `stow check`s a
throwaway consumer crate in mock-key mode until the artifact is served
from the cache. It then exercises the host-side node pipeline:
`snafu-derive`'s proc-macro tree submits as host-side tasks gated on
published slices, builds wave by wave with an export → publish → report →
sync pass between layers, and serves a second consumer both natively and
under `--target wasm32-unknown-unknown`. For the edge it runs
`skyzen build` once and supervises
`wrangler dev` itself, because `skyzen dev`'s file watcher rebuilds in
a loop on Linux — inotify reports opens of the watched manifest and
sources as changes, so every rebuild re-triggers itself. Everything
lives under one throwaway work dir (keys, registry root, edge state,
stow cache, logs), so it never touches your real stow or cargo state,
and every child is reaped by PID on exit:

```sh
scripts/mock-e2e.sh
```

The script prints its log directory at the end and dumps every log on
failure. Every port it binds is an environment override —
`STOW_E2E_EDGE_PORT`, `STOW_E2E_INSPECTOR_PORT`,
`STOW_E2E_REGISTRY_PORT`, `STOW_E2E_LOCAL_CI_PORT` — with the recipe's
values as defaults, so a second run can share the machine by shifting
the set (the edge bundle's loopback URLs are rendered to match at
`skyzen build` time). CI runs it in the release gate (`mock-e2e` in
`.github/workflows/release-gate.yml`) — on demand, nightly on `dev`,
and on every pull request and merge group into `main` — which is what
keeps the trusted build path — dispatch → build → publish → CLI cache
hit — continuously tested on a clean runner.

## Traffic cost

`scripts/traffic-cost.sh` runs the same three services against the
production-shaped scheduler fixture instead of a single crate, and
answers whether launch user traffic fits the Cloudflare allowance
without overloading the scheduler. In one stack start it:

1. seeds the fixture at 20k and then 10k queue rows and runs every
   scheduler drive (`edge/src/scheduler/drives.rs`) through the Durable
   Object's budget probe, reading workerd's billed `rowsRead` and
   `rowsWritten`;
2. measures Worker CPU per traffic lane with the isolate's V8 CPU
   profiler, reached through `wrangler dev --inspector-port`
   (`stow-admin traffic-cost cpu`);
3. drives every lane at the launch model's peak rate for thirty
   minutes (`stow-admin traffic-cost peak`);
4. runs the drives again on the loaded fixture;
5. judges the run (`stow-admin traffic-cost verdict`): row budgets,
   growth with stored rows, and peak serialized Durable Object wall.

The monthly projection against 80% of each product's allowance is the
release gate's separate `Monthly projection` job (`stow-admin
traffic-cost project`): it prices user traffic from this run's
`reports/budget-small.json`, `budget-after.json` and `worker-cpu.json`
at the launch model's rates, then adds the preheat the Preheat cost job
measured — see below.

Between steps it waits until the dispatch stub reports no build run in
progress, so a dispatch callback from one step never lands in the next
step's measurement, and it stops the services in reverse start order.
Every lane stays on the machine except the trusted endpoints' GitHub
push-permission check. The tunables are listed in
`docs/ENVIRONMENT.md`. CI runs it as the release gate's `Traffic cost`
job and uploads `reports/` on every run.

```sh
GH_TOKEN=$(gh auth token) scripts/traffic-cost.sh
```

The rest of this doc is the manual recipe the script automates, with
the topology and verification details behind it. Follow it when you
want the services left running, a larger preheat than a single crate,
or a real consumer project instead of the throwaway one.

## Preheat cost

`scripts/preheat-cost.sh` runs a whole preheat wave on the same three
services and prices it in the rows the scheduler Durable Object is
billed for (stow#773). The production lanes — `preheat
top-binaries` and `preheat projects submit` over `preheat/projects.toml`
— submit the real resolved graph across every CI target while the
wave runs; every dispatch is a real `stow-build build` and publish
validation whose rustc invocations a mock compiler answers with empty
outputs (`STOW_BUILD_MOCK_COMPILE`, compiled in only with the
`mock-compile` feature) and answers as the host of the runner the
task's target is dispatched to, so one machine builds every target's
host-side nodes as its runner would; publish rounds release the graph layer by
layer; then the same lists are resubmitted the way the daily cron
does. The edge runs the budget-probe manifest at production's
dispatch caps and cost multiplier, and its probe ledger (`stow-admin
preheat cost ledger`) is read at every lane and round boundary.

`stow-admin preheat cost report` turns the run into
`preheat-cost-report.json` — per event kind (submit, alarm dispatch,
completion, slice report) per layer, wave and resubmit totals, nodes
per target, wall time — and fails when the wave or resubmit totals
pass the preheat budget in `types/src/do_budgets.rs`, a per-event cost
grows from the first layer to the last past the scheduler-budget
tolerance, a node is dispatched before its dependencies are
published, a submitted node never publishes, or the object answers
`overloaded`. The full wave is CI-sized; locally, reduce it:

```sh
STOW_PREHEAT_COST_TARGETS="$(rustc -vV | sed -n 's/^host: //p')" \
STOW_PREHEAT_COST_LIMIT=3 STOW_PREHEAT_COST_PROJECTS=2 \
  scripts/preheat-cost.sh
```

`docs/ENVIRONMENT.md` lists every tunable.

## Production wave

The monthly projection needs the production wave's size, and counting
it needs no mock stack. `scripts/production-wave.sh` runs the three
production lanes — `preheat top-binaries` and `preheat
projects submit` — at `preheat-admin.yml`'s default limit and targets,
concurrently and plan-only: without `--yes` a lane resolves and prints
the tasks it would submit and never connects to an edge, so nothing is
enqueued. `stow-admin preheat cost production` then counts the distinct
task identities across the lanes into `production-wave.json`, and fails
when a lane exited non-zero or planned nothing. It is the release
gate's own `Production wave` job because production's resolve takes up
to 100 minutes (the projects lane) and would otherwise compete with the
Preheat cost job's wave for the runner.

```sh
scripts/production-wave.sh
```

## Monthly projection

The release gate's `Monthly projection` job divides the Preheat cost
report's wave and resubmit totals by the reduced wave's node count and
multiplies by the production count: one wave per stable rustc release
(`[cadence]` in `launch-model.toml`, counted from Rust's release
history by `stow-admin launch-model export`) plus one resubmit per day,
added to each product's traffic before comparing with half its
allowance. `stow-admin traffic-cost project` takes the report as
`--preheat` and the count as `--production`. Only the scheduler Durable
Object's billed calls and rows are measured; the table marks every
other dimension `n/m` and prices it from traffic alone.

## Prerequisites

```sh
brew install hyperfine sqlite3
npm i -g wrangler@4    # or use the version pinned in skyzen/cli
cargo install wasm-bindgen-cli --version 0.2.120  # match Cargo.lock
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/zen-rs/skyzen/releases/download/skyzen-cli-v0.4.2/skyzen-cli-installer.sh | sh  # provides `skyzen dev`/`deploy`/`provision`/`secret`
```

You also need a sigstore-loadable PEM key pair. ECDSA P256 in PKCS#8
form works; macOS's default `openssl ec` produces SEC1 PEM that
sigstore rejects, so convert:

```sh
mkdir -p /tmp/stow-bench/keys
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/stow-bench/keys/private.pem
openssl pkcs8 -topk8 -nocrypt -in /tmp/stow-bench/keys/private.pem -out /tmp/stow-bench/keys/private.pkcs8.pem
mv /tmp/stow-bench/keys/private.pkcs8.pem /tmp/stow-bench/keys/private.pem
openssl ec -in /tmp/stow-bench/keys/private.pem -pubout -out /tmp/stow-bench/keys/public.pem
```

Build the workspace binaries once:

```sh
cd /path/to/stow
cargo build --release -p stow-cli -p stow-build -p stow-mock-registry -p stow-admin
```

## Topology

```
┌──────────────────────────────┐    POST /api/v1/scheduler/tasks/submit
│ stow-admin (host)            │────────────────────────────────────────┐
└──────────────────────────────┘                                        │
         │ POST /api/v1/admin/index/{target}/{rustc} (index report)      ▼
┌──────────────────────────────┐  POST {STOW_LOCAL_CI_URL}/dispatch  ┌──────────────┐
│ wrangler dev (port 8788)     │────────────────────────────────────►│ stow-build   │
│ stow-edge wasm + miniflare   │  POST /api/v1/github/workflow-run   │ local CI     │
│ Durable Object               │◄────────────────────────────────────│ port 28124   │
└──────────┬───────────────────┘                                     └─────┬────────┘
           │ GET /api/v1/bundles/{rustc_version}/{digest} (bundle bytes), POST /api/v1/admissions │ bundles + records
           ▲                                                               │ sigstore push
┌──────────┴───────────────────┐                                           ▼
│ stow-cli (consumer machine)  │  OCI pulls: signed index.* slices ┌──────────────────┐
│ index slice cached locally   │◄──────────────────────────────────│ stow-mock-registry│
└──────────────────────────────┘                                   │ port 28123 (serve)│
                                                                   └──────────────────┘
```

The trust path is unchanged from production: stow-build signs and
pushes the bundle and the records artifact to the mock registry — it
never calls the edge — and reports completion through the same
`workflow_run` webhook shape GitHub sends, HMAC-signed with the
fixture's `STOW_GITHUB_WEBHOOK_SECRET`. `stow-admin index report` then
tells the scheduler which identities each published slice serves,
behind the developer's GitHub token (`GH_TOKEN`/`GITHUB_TOKEN`, else
`gh auth token`), which the edge checks for push access to
`water-rs/stow` — against the mock registry's GitHub stub
(`STOW_GITHUB_API_URL`), never the real API.

## Bring services up

Open three terminals (or use `tmux`/background processes).

**Terminal 1 — mock OCI registry:**

```sh
mkdir -p /tmp/stow-bench/mock-registry
target/release/stow-mock-registry serve --registry-root /tmp/stow-bench/mock-registry
```

Verify: `curl -i http://127.0.0.1:28123/v2/` returns `401 Unauthorized`
with a `WWW-Authenticate` Bearer challenge — that is how the version ping
behaves on GHCR, and how `oci-client` discovers the token realm.

The mock speaks GHCR's anonymous token exchange, so the pull path is
exercised end to end: `/v2/…` requests without a bearer get `401` plus a
`WWW-Authenticate` challenge pointing at
`http://127.0.0.1:28123/token`, `GET /token?service=…&scope=…` mints a
bearer (kept in server memory with a 300 s expiry), and only requests
carrying a registry-issued token are served.

**Terminal 2 — edge worker:**

`skyzen dev` rebuilds the wasm and starts Wrangler. Pin `--port 8788` so
it matches the scheduler URL and env vars used everywhere below (extra
args are forwarded to `wrangler dev`). To run Wrangler manually instead,
use the prebuilt artifacts skyzen leaves under `edge/`:

```sh
cd edge
skyzen build --provider cloudflare --manifest Skyzen.mock.toml
skyzen dev --provider cloudflare --manifest Skyzen.mock.toml --port 8788 \
    --persist-to /tmp/stow-bench/edge-state
# OR:
wrangler --config /path/to/edge/.skyzen/gen/wrangler.toml dev --local --port 8788 \
    --persist-to /tmp/stow-bench/edge-state
```

The scheduler Durable Object
keeps its own SQLite store, and request code never creates it — the
reset is operations work. Run the same operator reset `stow-admin`
offers, in a fourth shell once Wrangler is listening (any HTTP response
is enough — the scheduler routes are 500s until the schema exists):

```sh
# Prints `scheduler store reset — <n> objects dropped` and stamps the
# configured dispatch floor.
STOW_EDGE_URL=http://127.0.0.1:8788 GH_TOKEN="$(gh auth token)" \
    target/release/stow-admin scheduler reset --yes
```

Verify: `curl http://127.0.0.1:8788/api/v1/scheduler/status` returns
`{"pending":0,"dispatched":0,"running":0,"completed":0,"failed":0}` —
a 500 `no such table: queue` means the reset step did not run.

**Terminal 3 — local CI dispatch endpoint:**

```sh
STOW_EDGE_URL=http://127.0.0.1:8788 \
STOW_GITHUB_WEBHOOK_SECRET=mock-github-webhook-secret \
STOW_MOCK_PUBLIC_KEY_PATH=/tmp/stow-bench/keys/public.pem \
STOW_MOCK_PRIVATE_KEY_PATH=/tmp/stow-bench/keys/private.pem \
STOW_MOCK_REGISTRY_ROOT=/tmp/stow-bench/mock-registry \
target/release/stow-build serve --listen 127.0.0.1:28124
```

Verify: the log prints `local CI server listening listen=127.0.0.1:28124`.

## Configure the CLI

```sh
mkdir -p ~/Library/Application\ Support/stow  # macOS path; ~/.config/stow on Linux
cat > ~/Library/Application\ Support/stow/config.toml <<EOF
edge_url = "http://127.0.0.1:8788"
registry_base_url = "http://127.0.0.1:28123"
verify_mode = "mock-key"   # needs a stow-cli built with --features mock-verify
mock_public_key_path = "/tmp/stow-bench/keys/public.pem"
EOF
```

`registry_base_url` redirects the CLI's index-slice pulls at the mock.
Bundle bytes stream through the mock edge, whose `GHCR_BASE_URL`
(`edge/Skyzen.mock.toml`) points at the same mock registry; the edge is
asked for admissions only when the index reports a miss.

## Populate the cache

**Top binaries** — the top-N crates whose default version ships a binary
target, ranked by the last 90 days of `version_downloads` in the crates.io
database dump (fetched once), each resolved as a name source through the
crate lane (each one's bundled `Cargo.lock` is dropped like every lane's,
so tasks land on the latest semver-compatible versions):

```sh
STOW_EDGE_URL=http://127.0.0.1:8788 GH_TOKEN="$(gh auth token)" \
target/release/stow-admin preheat top-binaries \
  --targets aarch64-apple-darwin --rustc-version 1.91.1 --limit 100 --yes
```

Watch the queue drain:

```sh
watch -n 2 "curl -sS http://127.0.0.1:8788/api/v1/scheduler/status"
```

Each task spawns a `cargo build` that captures every transitive rustc
invocation; expect 30 s – 2 min per task on a fast machine. Top-100
binary preheat compiles thousands of crates; let it run on dedicated
CPU.

## Verify

The populated records feed the signed index the CLI resolves against —
export the slice out of the registry's records artifacts and publish it
back into the mock registry (mock-key mode delegates the signed push to
`stow-mock-registry publish-index`):

```sh
STOW_EDGE_URL=http://127.0.0.1:8788 GH_TOKEN="$(gh auth token)" \
target/release/stow-admin index export \
  --out-dir /tmp/stow-bench/index-export --rustc-version 1.91.1
STOW_MOCK_PRIVATE_KEY_PATH=/tmp/stow-bench/keys/private.pem \
STOW_MOCK_REGISTRY_ROOT=/tmp/stow-bench/mock-registry \
target/release/stow-admin index publish \
  --file /tmp/stow-bench/index-export/index.aarch64-apple-darwin.1.91.1 \
  --folded /tmp/stow-bench/index-export/folded.aarch64-apple-darwin.1.91.1
STOW_EDGE_URL=http://127.0.0.1:8788 GH_TOKEN="$(gh auth token)" \
target/release/stow-admin index report \
  --file /tmp/stow-bench/index-export/index.aarch64-apple-darwin.1.91.1
```

Then refresh the consumer-side cache and run `stow check` against a
popular project:

```sh
git clone --depth 1 https://github.com/BurntSushi/ripgrep /tmp/stow-bench/ripgrep
rustup run stable stow index refresh   # pulls + verifies the signed slice
rustup run stable stow index status    # target/rustc/rows/manifest-digest
rustup run stable stow check --silent-compatible-upgrades \
  --manifest-path /tmp/stow-bench/ripgrep/Cargo.toml
stow status   # rust-cache: hits=N misses=M errors=0
```

A row only hits when the cached artifact's `dependency_c_metadata_json`
matches the consumer's resolved graph — which is why the wave preheats
binary closures rather than standalone-built libraries. After `preheat
top-binaries --limit 100`, many real-project lockfiles overlap enough
with the binary closures that the wrapper's exact-key path starts
hitting.

## Forced eviction

`scripts/eviction-check.sh` kills the local workerd while a dispatch
pass is posting its claims, restarts it over the same persisted
Durable Object storage and asserts the woken scheduler lost no task
and dispatched none twice. It needs the host binaries built
(`cargo build -p stow-admin -p stow-build -p stow-mock-registry`) and
the edge bundle (`skyzen build --provider cloudflare --manifest
edge/Skyzen.mock.toml`).

## Tearing down

The mock registry, wrangler, and stow-build endpoints are plain
processes; `kill <pid>` is enough. State on disk
(`/tmp/stow-bench/{mock-registry,edge-state}`) persists across restarts;
delete those directories to start fresh.