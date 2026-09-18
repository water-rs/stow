# End-to-end mock recipe

For local development you can run the entire pipeline against three
local processes — no Cloudflare account, no GitHub Actions, no real
GHCR — by chaining `stow-mock-registry`, a Wrangler dev edge, and the
`stow-build` local-CI dispatch endpoint.

## One-command run

`scripts/mock-e2e.sh` is the canonical way to run this recipe. It does
the whole thing unattended — builds the binaries, generates the P-256
key pair, starts all three services, submits one `itoa` task through
`stow-admin`, waits out the scheduler, and `stow check`s a throwaway
consumer crate in mock-key mode until the artifact is served from the
cache. For the edge it runs `skyzen build` once and supervises
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
failure. CI runs it on every PR and push (`mock-e2e` in
`.github/workflows/test.yml`), which is what keeps the trusted build
path — dispatch → build → register → CLI cache hit — continuously
tested on a clean runner.

The rest of this doc is the manual recipe the script automates, with
the topology and verification details behind it. Follow it when you
want the services left running, a larger preheat than a single crate,
or a real consumer project instead of the throwaway one.

## Prerequisites

```sh
brew install hyperfine sqlite3
npm i -g wrangler@4    # or use the version pinned in skyzen/cli
cargo install wasm-bindgen-cli --version 0.2.120  # match Cargo.lock
cargo install skyzen-cli --version 0.3.0  # provides `skyzen dev`/`deploy`/`provision`/`secret`
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
cargo build -p stow-cli -p stow-build -p stow-mock-registry -p stow-admin
```

## Topology

```
┌──────────────────────────────┐    POST /api/v1/scheduler/tasks/submit
│ stow-admin (host)            │────────────────────────────────────────┐
└──────────────────────────────┘                                        │
                                                                        ▼
┌──────────────────────────────┐  POST {STOW_LOCAL_CI_URL}/dispatch  ┌──────────────┐
│ wrangler dev (port 8788)     │────────────────────────────────────►│ stow-build   │
│ stow-edge wasm + miniflare   │  POST /api/v1/admin/artifacts/      │ local CI     │
│ D1, Durable Object           │◄──────────────── register ──────────│ port 40124   │
│                              │  POST /api/v1/scheduler/complete    │              │
│                              │◄────────────────────────────────────│              │
└──────────┬───────────────────┘                                     └─────┬────────┘
           │ GET /v2/.../blobs                                             │ HTTP push
           ▼                                                               ▼
┌──────────────────────────────┐                                  ┌──────────────────┐
│ stow-mock-registry           │◄─────────────────────────────────│ stow-mock-registry│
│ port 40123 (HTTP serve)      │      OCI manifest + cosign        │   populate       │
└──────────────────────────────┘                                  └──────────────────┘
```

The trust path is unchanged from production: stow-build POSTs an
`x-stow-register-token` to the edge admin endpoint to write D1 records.
The edge owns the only D1-write credential.

## Bring services up

Open three terminals (or use `tmux`/background processes).

**Terminal 1 — mock OCI registry:**

```sh
mkdir -p /tmp/stow-bench/mock-registry
target/debug/stow-mock-registry serve --registry-root /tmp/stow-bench/mock-registry
```

Verify: `curl -i http://127.0.0.1:40123/v2/` returns `200 OK`.

**Terminal 2 — edge worker:**

`skyzen dev` rebuilds the wasm and starts Wrangler. Pin `--port 8788` so
it matches the scheduler URL and env vars used everywhere below (extra
args are forwarded to `wrangler dev`). To run Wrangler manually instead,
use the prebuilt artifacts skyzen leaves under `edge/`:

```sh
cd edge
skyzen dev --provider cloudflare --manifest Skyzen.mock.toml --port 8788 \
    --persist-to /tmp/stow-bench/edge-state
# OR:
wrangler --config /path/to/edge/.skyzen/gen/wrangler.toml dev --local --port 8788 \
    --persist-to /tmp/stow-bench/edge-state
```

Verify: `curl http://127.0.0.1:8788/api/v1/scheduler/status` returns
`{"pending":0,"dispatched":0,"running":0,"completed":0,"failed":0}`.

**Terminal 3 — local CI dispatch endpoint:**

```sh
SCHEDULER_URL=http://127.0.0.1:8788/api/v1/scheduler \
STOW_EDGE_URL=http://127.0.0.1:8788 \
STOW_MOCK_PUBLIC_KEY_PATH=/tmp/stow-bench/keys/public.pem \
STOW_MOCK_PRIVATE_KEY_PATH=/tmp/stow-bench/keys/private.pem \
STOW_MOCK_REGISTRY_ROOT=/tmp/stow-bench/mock-registry \
SCHEDULER_AUTH_TOKEN=local-scheduler-token \
STOW_REGISTER_AUTH_TOKEN=local-register-token \
target/debug/stow-build serve --listen 127.0.0.1:40124
```

Verify: the log prints `local CI server listening listen=127.0.0.1:40124`.

## Configure the CLI

```sh
mkdir -p ~/Library/Application\ Support/stow  # macOS path; ~/.config/stow on Linux
cat > ~/Library/Application\ Support/stow/config.toml <<EOF
edge_url = "http://127.0.0.1:8788"
verify_mode = "mock-key"
mock_public_key_path = "/tmp/stow-bench/keys/public.pem"
EOF
```

## Populate the cache

Two preheat shapes are useful:

**Library base pool** — top-N popular libraries with default features:

```sh
STOW_EDGE_URL=http://127.0.0.1:8788 SCHEDULER_AUTH_TOKEN=local-scheduler-token \
target/debug/stow-admin preheat-t100 \
  --target aarch64-apple-darwin --rustc-version 1.91.1 --limit 100
```

**Binary-derived overlay** — top-N binaries with their own `Cargo.lock`
preserved (this is the only mode that makes `cargo install --locked
<bin>` hit cache, because c_metadata matches by construction):

```sh
STOW_EDGE_URL=http://127.0.0.1:8788 SCHEDULER_AUTH_TOKEN=local-scheduler-token \
target/debug/stow-admin preheat-binary-overlay \
  --target aarch64-apple-darwin --rustc-version 1.91.1 --limit 100
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

```sh
sqlite3 /tmp/stow-bench/edge-state/v3/d1/miniflare-D1DatabaseObject/*.sqlite \
  "SELECT count(*) FROM artifacts; SELECT count(DISTINCT crate_name) FROM artifacts"
```

Then run `stow check` against a popular project:

```sh
git clone --depth 1 https://github.com/BurntSushi/ripgrep /tmp/stow-bench/ripgrep
rustup run stable stow check --silent-compatible-upgrades \
  --manifest-path /tmp/stow-bench/ripgrep/Cargo.toml
stow status   # rust-cache: hits=N misses=M errors=0
```

If you only ran `preheat-t100` you'll typically see hits=0 because
standalone-built libraries produce different `dependency_c_metadata_json`
than ripgrep's own lockfile resolution. That's expected — this is what
the binary overlay solves. After `preheat-binary-overlay --limit 100`,
many real-project lockfiles overlap enough with the binary closures that
the wrapper's exact-key path starts hitting.

## Tearing down

The mock registry, wrangler, and stow-build endpoints are plain
processes; `kill <pid>` is enough. State on disk
(`/tmp/stow-bench/{mock-registry,edge-state}`) persists across restarts;
delete those directories to start fresh.
