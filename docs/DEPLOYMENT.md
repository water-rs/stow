# Deployment

This document describes how to deploy the production trust topology:

```
GitHub Actions ──records artifact (cosign-signed)──► GHCR (OCI)
     ▲                                               │
     │ workflow_dispatch                             │ reads + verifies
     │                                               ▼
     └─── Scheduler DO ──► Edge Worker ──D1──► Cloudflare D1
                               ▲
     GitHub webhook ──workflow_run──┘
```

CI is the only producer of artifacts and writes them — bundles and
records alike — straight into GHCR; the edge owns the D1 binding and
learns build completion from GitHub's `workflow_run` webhook; end
users only ever talk to the edge. Detailed trust analysis lives in
[`ARCHITECTURE.md`](ARCHITECTURE.md#trust-boundaries).

## One-time Cloudflare setup

The production manifest is [`edge/Skyzen.toml`](../edge/Skyzen.toml). It
declares the `STOW_DB` D1 database, the `Scheduler` Durable Object with its
`v1` migration, the five runtime `[[secret]]` names (never values), the
non-secret `vars`, and the `stow.waterui.dev` Workers Custom Domain via
`[cloudflare.raw]` routes.

1. Provision the D1 database once. `skyzen provision` creates `stow-prod`
   and writes `database_id` back into `edge/Skyzen.toml` — commit the
   result:

   ```sh
   skyzen provision --provider cloudflare --manifest edge/Skyzen.toml
   ```

2. Set the Worker secrets. Each name must be declared in `[[secret]]`
   first, which the manifest already does:

   ```sh
   skyzen secret set GITHUB_APP_PRIVATE_KEY  # stow-ci GitHub App PEM; same key as the STOW_APP_PRIVATE_KEY repository secret
   skyzen secret set STOW_POW_CHALLENGE_SECRET  # HMAC key for enqueue-admission challenges
   skyzen secret set TURNSTILE_SECRET_KEY       # Turnstile secret key paired with the TURNSTILE_SITE_KEY var
   skyzen secret set CF_ANALYTICS_TOKEN         # API token with Analytics Engine read, used by GET /api/v1/stats
   skyzen secret set STOW_GITHUB_WEBHOOK_SECRET # HMAC key verifying GitHub's workflow_run webhook (below)
   ```

   `CF_ANALYTICS_TOKEN` is an account-level API token (dashboard: *My
   Profile → API Tokens → Create Token → Create Custom Token*) with
   permission *Account → Account Analytics → Read* on this account — it
   is what `GET /api/v1/stats` uses to run the `edge/src/sql/stats_*.sql`
   queries against the Analytics Engine SQL API. The `CF_ACCOUNT_ID`
   var in the manifest names the account those queries run under.

   The one shared secret on the edge write surface is
   `STOW_GITHUB_WEBHOOK_SECRET` — it verifies GitHub's own
   `workflow_run` deliveries, which only GitHub can send. Every
   operator/CI-facing trusted endpoint still authenticates a GitHub
   identity, never a shared token (see
   [Trusted-endpoint authentication](#trusted-endpoint-authentication)).

3. Deploys run from GitHub Actions — see below. The first deploy also
   attaches the `stow.waterui.dev` custom domain (Cloudflare creates the
   DNS record in the `waterui.dev` zone automatically).

4. Give the weekly miss-promotion lane (`preheat-missed.yml`) read access
   to the `stow_cache_misses` Analytics Engine dataset. In the Cloudflare
   dashboard (*My Profile → API Tokens → Create Custom Token*) create a
   token with *Account → Account Analytics → Read* on this account, store
   it as the `CF_ANALYTICS_TOKEN` repository secret, and set the
   `CF_ACCOUNT_ID` repository variable to the account ID shown on any
   dashboard overview page.

5. Rate-limit the edge API. `/api/v1/enqueue` and `/api/v1/requests` are
   the two endpoints an anonymous client can use to consume CI, and
   `/api/v1/admissions` runs the miss-derivation pass over the artifact
   catalog — but enumerating paths would leave the other anonymous
   routes (request and scheduler status, routes added later) unlimited,
   so the rule matches the `/api/v1/` path prefix and carves out only
   `/api/v1/bundles/`. The byte path is excluded on purpose: a warm
   build streams its closure at the CLI's prefetch concurrency and the
   per-`rustc` wrapper fetches on demand under cargo's own job
   parallelism, so one address legitimately sends tens of bundle
   requests per second, and a block there turns a cache hit into a
   local compile mid-build. That path is the cheap one — a Cache API hit
   costs one Worker request and no D1 or Durable Object work — and its
   volume is bounded by the DDoS managed ruleset, the billing
   notifications below, and the zone maintenance rules rather than by
   this rule. The Free plan allows exactly one rate-limiting rule, which is
   why the split is an exclusion inside a single expression rather than
   a second, looser rule on artifacts.

   The rule counts per `ip.src` alone — adding `cf.colo.id` to the
   characteristics would hand each address a fresh budget in every
   Cloudflare data center it can reach — and the expression uses
   `starts_with` because the `matches` regex operator requires a Business
   plan. Requests a zone rule blocks never reach the Worker and are never
   billed, which is what makes this rule the cost backstop: the
   proof-of-work admission and the Turnstile check still guard the
   submission endpoints, but they run inside the Worker and only see the
   requests the zone lets through. CGNAT and IPv6 rotation mean a per-IP
   limit cannot be the whole defense.

   The limit is 60 requests per 10 seconds — a per-IP ceiling of
   ≈ 15.5 M requests per month on the limited paths, far above anything
   a real client sends there: the CLI solves and posts admissions
   sequentially on one worker thread, and a `predict` run sends each
   catalog call once. The 10 s period is the one every Cloudflare plan
   offers.

   The rule is appended to the zone's `http_ratelimit` phase (the token
   needs *Zone → Zone WAF → Edit* on `waterui.dev`; the Workers-scoped
   deploy token cannot do this). Appending keeps any rule already in the
   phase; a `PUT` on the phase entrypoint would replace the whole list.
   Rate-limiting rules are zone-scoped — there is no per-hostname place
   to attach one — so the rule is evaluated for every request into
   `waterui.dev`; the `/api/v1/` prefix only exists on the stow edge
   API, so the expression needs no `http.host` term.

   ```sh
   ruleset_id="$(curl -sS \
     "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/phases/http_ratelimit/entrypoint" \
     -H "Authorization: Bearer $CLOUDFLARE_ZONE_TOKEN" | jq -r '.result.id')"
   curl -sS -X POST \
     "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/$ruleset_id/rules" \
     -H "Authorization: Bearer $CLOUDFLARE_ZONE_TOKEN" \
     -H "Content-Type: application/json" \
     --data @- <<'JSON'
   {
     "description": "stow: per-IP limit on /api/v1/",
     "expression": "starts_with(http.request.uri.path, \"/api/v1/\") and not starts_with(http.request.uri.path, \"/api/v1/bundles/\")",
     "action": "block",
     "ratelimit": {
       "characteristics": ["ip.src"],
       "period": 10,
       "requests_per_period": 60,
       "mitigation_timeout": 10
     }
   }
   JSON
   ```

   To update a rule already in the phase, `PATCH` it by id (rule ids
   come from a `GET` on the ruleset):

   ```sh
   curl -sS -X PATCH \
     "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/$ruleset_id/rules/$RULE_ID" \
     -H "Authorization: Bearer $CLOUDFLARE_ZONE_TOKEN" \
     -H "Content-Type: application/json" \
     --data @- <<'JSON'
   {
     "description": "stow: per-IP limit on /api/v1/",
     "expression": "starts_with(http.request.uri.path, \"/api/v1/\") and not starts_with(http.request.uri.path, \"/api/v1/bundles/\")",
     "action": "block",
     "ratelimit": {
       "characteristics": ["ip.src"],
       "period": 10,
       "requests_per_period": 60,
       "mitigation_timeout": 10
     }
   }
   JSON
   ```

   A zone that has never had a rate-limiting rule has no
   `http_ratelimit` entrypoint yet (the first request returns 404);
   create it with the same rule as its only entry:

   ```sh
   curl -sS -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets" \
     -H "Authorization: Bearer $CLOUDFLARE_ZONE_TOKEN" \
     -H "Content-Type: application/json" \
     --data '{"name": "stow rate limiting", "kind": "zone", "phase": "http_ratelimit", "rules": [<the rule above>]}'
   ```

   The same rule in the dashboard: *Security → Security rules → Create
   rule → Rate limiting rules*, match `URI Path` `starts with`
   `/api/v1/` **and** `URI Path` `does not start with`
   `/api/v1/bundles/`, 60 requests per 10 seconds per IP, block for
   10 seconds.

6. **Maintenance rules (the breaker, stow#453).** Three WAF custom
   rules live on the zone's `http_request_firewall_custom` phase and are
   the anonymous-traffic breaker — a blocked request never invokes the
   Worker, so the shed costs nothing and a broken edge cannot keep it
   open:

   - `stow maintenance: anonymous` —
     `http.host eq "<edge host>" and not starts_with(http.request.uri.path, "/api/v1/admin") and not starts_with(http.request.uri.path, "/api/v1/scheduler")`,
     action `block`. Sheds every public route while the trusted CI and
     admin lanes keep working.
   - `stow maintenance: scheduler lanes` —
     `http.host eq "<edge host>" and (starts_with(http.request.uri.path, "<lane>") or …)`,
     action `block`, over exactly the public routes whose handlers reach
     the scheduler Durable Object (`scheduler_lanes` in
     `types/src/api.rs`). The bundle byte path and catalog reads keep
     serving — the partial reopening.
   - `stow maintenance: all` — `http.host eq "<edge host>"`,
     action `block`. The whole site down at zero usage.

   `<edge host>` is the host of `STOW_EDGE_URL` — the rules follow
   whichever edge they were ensured against. `deploy-edge.yml` runs
   `stow-admin maintenance ensure --yes` with the deployed commit's
   signed toolchain `stow-admin` (#431): it creates all three rules
   **disabled** and the `http_request_firewall_custom` entrypoint itself
   when the phase has never had a ruleset (the API answers error 10003),
   matching rules by `description`, so they exist before anyone needs
   them and a redeploy never stomps a live toggle. Toggle by hand:
   `stow-admin maintenance on|off --scope anonymous|lanes|all --yes`,
   with `CLOUDFLARE_API_TOKEN` (needs *Zone WAF → Edit* on
   `waterui.dev`), `CF_ZONE_ID` and `STOW_EDGE_URL` exported;
   `stow-admin maintenance status` prints the current state.

### Billing notifications

The zone rule bounds request volume; usage-based billing notifications
watch the spend itself. In the Cloudflare dashboard (*Notifications →
Add → Billing → Usage Based Billing*) create an alert for each
billable metric the edge consumes — Workers requests, D1 rows written,
and Durable Object requests — with the alert threshold at $8/month; the
project budget is $10/month. See the
[Cloudflare notifications docs](https://developers.cloudflare.com/notifications/notification-available/)
for the alert type.

## Automated deploys

`.github/workflows/deploy-edge.yml` deploys a tested commit only: on a
green `Test` run of a `main` push (`workflow_run`), and on
`workflow_dispatch`, which takes the commit `sha` (verified to have a
completed green `Test` run via `gh run list --commit`) plus
`canary_share` (default `5`).

No job waits: the deploy is four jobs, and the observation windows are
GitHub environment wait timers, which hold no runner. Operator setup
(once per repository): under Settings → Environments create

- `deploy-canary` — wait timer `15` minutes (the canary observation
  window, the `canary-verdict` job's delay);
- `deploy-promoted` — wait timer `15` minutes (the post-promotion
  window, the `promoted-verdict` job's delay).

Change a window by editing that environment's wait timer; the verdict
reads the window's bounds from timestamps, so nothing else moves.

The `prepare` job uploads the new Worker version without deploying it —
`skyzen deploy --upload-only` plans `wrangler versions upload`, and the
declared `[[secret]]` values travel in the same upload through
`--secrets-file` — then adds it to the deployment at `0%` so that
version overrides reach it, runs `stow-admin scheduler migrate` against
the candidate via the `Cloudflare-Workers-Version-Overrides` header
(the scheduler schema version stamp must equal the candidate's own
`SCHEMA_VERSION`, else the deploy fails before any traffic shifts),
fires the synthetic suite through the same override — 50 requests on the
candidate interleaved with 50 on the baseline across the site, crate
lookup, artifact HEAD, stats and scheduler status paths, the floor the
verdict's `--min-requests-per-version` expects on each side — and
finally shifts `canary_share`% of traffic onto it.

Promotion is gated on two verdict phases of
`stow-admin deploy verdict`, each printing every metric's baseline and
candidate values and exiting non-zero on a breach — which runs
`wrangler rollback` and fails that job:

- `--phase canary`, run by `canary-verdict` after the `deploy-canary`
  wait timer: worker error rate and cpu/wall-time p50/p99 per
  `scriptVersion` from `workersInvocationsAdaptive`, plus DO requests,
  errors and wall time per request per `scriptVersion` from
  `durableObjectsInvocationsAdaptiveGroups`. Both sides are measured in
  the same window — the suite pinned its requests to each version, so
  either side serving nothing or fewer than the suite's count fails
  closed; DO rows report `skipped` when the Scheduler object stayed on
  the baseline (objects are assigned one version per deployment config —
  a reassigned object is reset once, and SQLite state survives).
- `--phase promoted`, run by `promoted-verdict` after `promote` and the
  `deploy-promoted` wait timer: the metrics that carry no
  `scriptVersion` compare the post-promotion window against the
  equal-length window ending at the deploy start — DO cpu and rows
  read/written per DO request from `durableObjectsPeriodicGroups`, and
  D1 rows read/written per worker request from
  `d1AnalyticsAdaptiveGroups`. A breach here rolls back too.

`stow-admin` comes from the deployed commit's signed toolchain image —
`.github/actions/stow-toolchain` pulls
`ghcr.io/water-rs/stow-toolchain:<sha>-<platform>` and verifies the
cosign signature against the commit's own workflow sha, so nothing
compiles it at deploy time.

Required GitHub Actions secrets:

- `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` — Wrangler
  authentication for the deploy itself. The watchdog workflow
  (`watchdog.yml`) reuses `CLOUDFLARE_API_TOKEN` for its Cloudflare
  calls, so on top of the Workers deploy scopes the token also needs
  `Account Analytics:Read` (the GraphQL analytics and the
  `analytics_engine/sql` `overloaded`-event query), Email Sending
  (the `POST …/email/sending/send` alert mail), and `Zone WAF:Edit` on
  `waterui.dev` (the maintenance rules below and the watchdog's trip).
  The zone's id goes in the `CF_ZONE_ID` repository variable — the
  WAF step below and `stow-admin maintenance`/`watchdog` read it.
- `STOW_APP_PRIVATE_KEY` → Worker `GITHUB_APP_PRIVATE_KEY` — the same
  GitHub App private key release-plz mints tokens from (see Releases
  below).
- `STOW_POW_CHALLENGE_SECRET` → Worker `STOW_POW_CHALLENGE_SECRET` —
  HMAC key for enqueue-admission challenges (any strong random string).
- `STOW_TURNSTILE_SECRET_KEY` → Worker `TURNSTILE_SECRET_KEY` — the
  secret half of the Turnstile widget the request page embeds (site key
  `0x4AAAAAAE8LjhnMsqdVhiSp`, invisible mode, hostname
  `stow.waterui.dev`); `POST /api/v1/requests` verifies every submitted
  token against it.
- `CF_ANALYTICS_TOKEN` → Worker `CF_ANALYTICS_TOKEN` — the
  Analytics-Engine-read API token `GET /api/v1/stats` queries with.

Deploying by hand (with the same environment variables exported) is
equivalent:

```sh
skyzen deploy --provider cloudflare --manifest edge/Skyzen.toml
```

## CI runner (GitHub Actions)

Trusted builds are `.github/workflows/build-crate.yml` on `main` of
`water-rs/stow`. The scheduler dispatches it with `workflow_dispatch`
(`ref: main`, one `task` input carrying the JSON `BuildTaskPayload`);
the runner is picked from the task's target (`ubuntu-latest`,
`macos-14`, `windows-latest`). Add a target by extending the
`runs-on` map in the workflow.

The workflow is two jobs and needs no edge URL: `build` compiles the
crate with `contents: read` only — no secrets, no OIDC — and uploads
its output directory as a workflow artifact. `publish` runs only when
`build` succeeds: it downloads the output, validates it against the
task and an independently resolved dependency closure, and only then
pushes the bundle plus the task's `Vec<ArtifactRecord>` (as one signed
OCI artifact tagged `records-<rustc>-<task_id hash>`) to GHCR, cosign-signing both
(keyless, `id-token: write`). The job never calls the edge — GitHub's
`workflow_run` webhook delivery reports the outcome instead, and the
edge checks the records artifact exists before completing the task. See
[`ARCHITECTURE.md`](ARCHITECTURE.md#trust-boundaries) for what the
publisher checks.

`build-crate.yml` reads no repository variables — `run-name` carries
`<rustc>-<task_id>` so the webhook's `display_title` parses back into
the run's rustc and task id.

`GHCR_TOKEN` is the job's own `GITHUB_TOKEN` (`packages: write`), and
cosign signs with the job's OIDC identity, so the certificate subject is
`https://github.com/water-rs/stow/.github/workflows/build-crate.yml@refs/heads/main`
— the identity `stow_types::trusted_builder` pins and the CLI verifies.

`index-publish.yml` (the artifact-index lane) folds the signed
records artifacts into per-`(target, rustc)` slices and pushes them to
GHCR under the same keyless identity scheme (the pinned
`index-publish.yml` certificate identity). Its `stow_edge_url`
dispatch input is optional: when it names a live edge the job also
POSTs the rows to `/api/v1/admin/artifacts/sync` (the D1 `artifacts`
catalog mirror the admission gate reads) and prints the export report;
when empty — Cloudflare down or the edge unprovisioned — the publish
still lands.

Every artifact is a tag of the single GHCR package
`ghcr.io/water-rs/stow-cache` —
`{crate}.{version}-{target_short}-{rustc_short}-{feat_hash}-{c_metadata}{kind_suffix}` —
because GHCR creates each package private and offers no REST or GraphQL
call to change visibility: a per-crate package layout would have meant a
manual flip per crate ever cached. The edge pulls the package with no
credential at all — public GHCR packages grant
`repository:water-rs/stow-cache:pull` to the anonymous `GET /token`
exchange that `edge/src/ghcr.rs` drives on every `401` challenge. One
manual step remains after the first trusted build pushes
`ghcr.io/water-rs/stow-cache`: set the package visibility to public in
the `water-rs` org package settings ([GitHub's package visibility
docs](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility)).
That flip is one-time and covers the cache forever; until it happens the
exchange fails with the `401`/`403` the `FetchError` reports.

The edge authenticates `workflow_dispatch` with a GitHub App
installation token minted on the Worker: the `GITHUB_APP_ID`
(`4985635`) and `GITHUB_APP_INSTALLATION_ID` (`162649982`) vars plus
the `GITHUB_APP_PRIVATE_KEY` secret are used to sign an RS256 JWT
(WebCrypto) and exchange it at the GitHub API. The `stow-ci` App is
installed on `water-rs` (selected repositories: `water-rs/stow`) with
**Actions: Read and write**, which is the permission the dispatch call
requires. The `incident` issue record is the external watchdog's (#450)
— the App deliberately carries no `issues` grant, because the edge is
untrusted serving infrastructure. Minted tokens are
cached in the Durable Object's SQL storage and reused while more than
five minutes of validity remain.

The crucial property: CI never holds a Cloudflare API token, and no
shared secret exists anywhere on the edge write surface — every trusted
call is a GitHub identity, verified as described below.

### GitHub webhook — `workflow_run`

Task completion reaches the scheduler through GitHub's webhook, not
through CI: `build-crate.yml` sets `run-name` to `<rustc>-<task_id>` and a
repository webhook POSTs `workflow_run` `completed` events to
`https://stow.waterui.dev/api/v1/github/workflow-run`. Configure it once
in the repo settings:

- **Payload URL:** `https://stow.waterui.dev/api/v1/github/workflow-run`
- **Content type:** `application/json`
- **Secret:** the `STOW_GITHUB_WEBHOOK_SECRET` value (the edge verifies
  `X-Hub-Signature-256` with it)
- **Events:** *Workflow runs* only
- **Active:** on

The route accepts a delivery only when the run is `completed` for
`build-crate.yml` on `main`; it parses `display_title` into the run's
rustc and task id and completes the task only after the records
artifact for that task
exists and verifies in GHCR, so a spoofed success cannot mint a catalog
entry.

## Trusted-endpoint authentication

Every authenticated endpoint — the whole `/api/v1/admin/*` surface
(artifact sync, listing, inspection and prune, coverage, the
queue transitions, the admin index export, preheat
planning, operator status) plus `POST /api/v1/scheduler/tasks/submit` —
takes
`Authorization: Bearer <credential>` and resolves the credential to a
GitHub identity (`edge/src/github_auth.rs`). Two shapes are accepted:

- **GitHub Actions OIDC JWT.** `preheat-admin.yml`'s submit step mints
  a per-run JWT (`audience=$STOW_OIDC_AUDIENCE`), and so does
  `index-publish.yml` when it syncs the D1 catalog. The edge verifies
  the RS256 signature against GitHub's JWKS
  (`token.actions.githubusercontent.com/.well-known/jwks`, fetched per
  call) and pins `iss`, `aud` (to the `STOW_OIDC_AUDIENCE` var),
  `repository` (to the `GITHUB_REPO` var), `exp`/`nbf`, and
  `job_workflow_ref`. `tasks/submit` accepts any workflow running inside
  the trusted repo. Nothing is stored or rotated — a leaked run token
  dies with the run.
- **Repo-push credential.** `stow-admin` and the local dev loop send the
  operator's own credential (`GH_TOKEN`/`GITHUB_TOKEN`, else `gh auth
  token`). The edge probes push capability directly — a GET on the repo's
  `git-receive-pack` ref advertisement answers 200 only when GitHub would
  accept a push from that credential — which works uniformly for user
  tokens, fine-grained PATs, and installation tokens like the mock-e2e
  job's `GITHUB_TOKEN` (REST permission fields do not reflect job-scoped
  installation tokens). Access follows GitHub role changes — revoke by
  removing push access, nothing to rotate.

Upstream GitHub failures return `502 github trust upstream unavailable`
(so CI retries); every credential failure returns `401`. The trusted
caller — `actions:<job_workflow_ref> run <id>` or `push:<login>` — is
recorded in the worker log on each write.

## Initial cache population

The cache preheats itself — `preheat-cron.yml` dispatches a wave
daily and on every new stable rustc. To seed it by hand — including
while Cloudflare is fully offline — `preheat manual` needs only a
GitHub credential with push access to `water-rs/stow` and network to
crates.io and GHCR; it resolves the graph, dispatches
`build-crate.yml` runs itself, and publishes each index slice as its
layer lands:

```sh
GH_TOKEN=<operator token> \
stow-admin preheat manual \
    --crates crates.txt \        # one `name` or `name@version` per line
    --rustc-version 1.91.1     --in-flight 45                # default; stays under the 60-runner pool
```

The same driver takes `--projects preheat/projects.toml` for a
repository list and `--edge-url https://stow.waterui.dev` (or
`STOW_EDGE_URL`) when the edge is up and the D1 sync should run. It is
resumable — coverage is recomputed from the published index, so a
re-run dispatches only what is still missing — and exits non-zero with
the failed runs' URLs when any task does not land.

The scheduler-driven lanes still work the same way when the edge is up —
from a machine that has `STOW_EDGE_URL` exported and the same GitHub
credential:

```sh
stow-admin preheat top-binaries \
    --targets x86_64-unknown-linux-gnu,aarch64-apple-darwin \
    --rustc-version 1.91.1 --limit 100 --yes
```

Each invocation enqueues the resolved crate tasks and returns immediately. The
scheduler dispatches them to GitHub Actions in parallel (subject to
`STOW_MAX_CONCURRENT_JOBS`, default 45, the per-family
`STOW_MAX_CONCURRENT_MACOS_JOBS`, default 16, and
`STOW_DISPATCH_MIN_AGE_MINUTES`; failed dispatches retry with
exponential backoff and tasks stuck in `dispatched` for
`STOW_STALE_DISPATCH_MINUTES`, default 60, are re-queued).

For first-time bring-up, also run `preheat top` for the library base
pool. The library pool and the binary pool are independent.

## Operating

- **Queue introspection:** `curl https://your-edge/api/v1/scheduler/status`
- **Under attack:** `stow-admin maintenance on --scope anonymous`, watch
  the request graph, `stow-admin maintenance off --scope anonymous`. The
  rule lives on the `waterui.dev` zone's `http_request_firewall_custom`
  phase — blocked requests never invoke the Worker — and the trusted CI
  endpoints keep working. `--scope lanes` sheds only the scheduler-backed
  lanes (bundle bytes keep serving); `--scope all` takes the whole
  hostname down. `stow-admin maintenance status` prints all three
  rules' state.
- **D1 row count:** `wrangler d1 execute stow-prod --command "SELECT count(*) FROM artifacts"`
- **GHCR storage:** the whole cache is the single `ghcr.io/water-rs/stow-cache`
  package (every artifact a tag); monitor disk via the GitHub UI.
- **Revoking trusted access:** there is no shared credential to rotate.
  CI access is the `build-crate.yml` OIDC identity itself — revoke by
  removing the workflow or narrowing the `job_workflow_ref` pin in
  `edge/src/github_auth.rs`. A user's access is their repo push
  permission — revoke on GitHub, effective within
  `PUSH_VERDICT_TTL_SECS` (5 minutes): the edge caches the push-capable
  verdict per credential for that long rather than re-probing GitHub on
  every call, since the per-request probe is what shared Cloudflare
  egress got rate-limited. Denied verdicts expire sooner
  (`PUSH_DENIED_TTL_SECS`, 1 minute), and an isolate restart cold-starts
  the cache — so revocation can also land sooner, never later.

## Releases

`stow-cli` ships prebuilt binaries via
[cargo-dist](https://axodotdev.github.io/cargo-dist/book/); the
configuration lives in `dist-workspace.toml` and only the `stow-cli`
package is distributed (the other binary crates are internal tooling).

The flow:

1. Changes land on `dev`. On every push to `dev`, `release-plz.yml`
   runs `release-plz release-pr`: it opens (or updates) a release PR
   against `dev` with the version bump and changelog. That PR merges
   like any other change.
2. A `dev` → `main` PR promotes `dev` to `main` (`main` accepts pull
   requests from `dev` only). On the push to `main`, `release-plz.yml`
   runs `release-plz release`: every crate whose version is not yet on
   crates.io is published over OIDC trusted publishing and tagged
   `<crate>-vX.Y.Z` (`stow-types-v*`, `stow-shim-v*`, `stow-oci-v*`,
   `stow-cli-v*`);
   only the `stow-cli-v*` tag starts a cargo-dist build.
3. The tag push triggers `release.yml` (cargo-dist), which builds
   `stow-cli` for `x86_64-unknown-linux-gnu`,
   `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`, and
   `x86_64-pc-windows-msvc`, then creates the
   GitHub Release and attaches the archives, the shell and PowerShell
   installers, and `sha256` checksums.

Required GitHub App configuration:

| Kind | Name | Value |
|---|---|---|
| variable | `STOW_APP_ID` | the GitHub App's ID |
| secret | `STOW_APP_PRIVATE_KEY` | the GitHub App's private key (PEM) |

The App is installed on `water-rs/stow` with **Contents: Read and
write** and **Pull requests: Read and write** (plus **Actions: Read and
write**, which the scheduler uses — see issue #33).

Both `release-plz.yml` jobs mint an installation token for the App and
use it for checkout and release-plz rather than the default
`GITHUB_TOKEN`: pull requests opened and tags pushed with `GITHUB_TOKEN`
never trigger other workflows, so the release PR's checks would never
run and the cargo-dist release run would never start; the App token does
trigger them, and it expires in an hour. release-plz creates the tag
but not the GitHub Release (`git_release_enable = false` in
`release-plz.toml`) — cargo-dist owns the release so it can attach the
artifacts.

## What deploys do NOT include

- The CLI binary (`stow`) is distributed via crates.io / GitHub
  Releases, not via the edge.
- The local-CI dispatch endpoint and mock-registry are dev-only;
  production never runs them.
