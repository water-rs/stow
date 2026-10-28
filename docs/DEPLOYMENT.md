# Deployment

This document describes how to deploy the production trust topology:

```
GitHub Actions ──records artifact (cosign-signed)──► GHCR (OCI)
     ▲                                               │
     │ workflow_dispatch                             │ reads + verifies
     │                                               ▼
     └─── Scheduler DO ──► Edge Worker
                               ▲
     GitHub webhook ──workflow_run──┘
```

CI is the only producer of artifacts and writes them — bundles and
records alike — straight into GHCR; the edge learns build completion
from GitHub's `workflow_run` webhook; end users only ever talk to the
edge. Detailed trust analysis lives in
[`ARCHITECTURE.md`](ARCHITECTURE.md#trust-boundaries).

## One-time Cloudflare setup

The production manifest is [`edge/Skyzen.toml`](../edge/Skyzen.toml). It
declares the `Scheduler` Durable Object with its
`v1` class declaration, the seven runtime `[[secret]]` names (never values), the
non-secret `vars`, and the `stow.waterui.dev` Workers Custom Domain via
`[cloudflare.raw]` routes.

1. Set the Worker secrets. Each name must be declared in `[[secret]]`
   first, which the manifest already does:

   ```sh
   skyzen secret set GITHUB_APP_PRIVATE_KEY  # stow-ci GitHub App PEM; same key as the STOW_APP_PRIVATE_KEY repository secret
   skyzen secret set STOW_POW_CHALLENGE_SECRET  # HMAC key for enqueue-admission challenges
   skyzen secret set TURNSTILE_SECRET_KEY       # Turnstile secret key paired with the TURNSTILE_SITE_KEY var
   skyzen secret set CF_ANALYTICS_TOKEN         # API token with Analytics Engine read, used by GET /api/v1/stats
   skyzen secret set STOW_GITHUB_WEBHOOK_SECRET # HMAC key verifying GitHub's workflow_run webhook (below)
   skyzen secret set STOW_NEWRELEASES_WEBHOOK_SECRET # HMAC key verifying newreleases.io deliveries (below)
   skyzen secret set STOW_STATS_SALT_SECRET     # key for the daily install-hash salt of the usage statistics
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
   [Trusted-endpoint authentication](#trusted-endpoint-authentication)),
   and every mutation runs through `operations.yml` (see
   [Operator mutations](#operator-mutations)).

2. Deploys run from GitHub Actions — see below. The first deploy also
   attaches the `stow.waterui.dev` custom domain (Cloudflare creates the
   DNS record in the `waterui.dev` zone automatically).

3. Initialize the scheduler store. The scheduler Durable Object's
   schema exists only through the operator reset route — once the first
   deploy is live and the `operations` environment exists (see
   [Operator mutations](#operator-mutations)):

   ```sh
   STOW_EDGE_URL=https://stow.waterui.dev stow-admin scheduler reset --yes
   ```

   The command dispatches `operations.yml`, prints the run URL and
   follows the run to its end; the reset appends a `StoreReset` row
   carrying the dispatcher's login as the fresh log's first row. The
   same pass is how a schema change lands: it drops every table,
   index and trigger in the store and re-executes
   `edge/src/scheduler/schema.sql`; the queue and recorded slices are
   destroyed and refill from the lanes that feed them. A stored record
   whose shape changes — the dispatch freeze's manual trigger carries
   its `actor` — is part of that schema, so a deploy that changes one is
   followed by the reset.

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
   local compile mid-build. That path is the cheap one — a Workers Cache
   hit is billed as a request but the Worker never runs: no CPU,
   subrequests, or Durable Object work — and its
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

8. **Maintenance rules (the breaker, stow#453).** Three WAF custom
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
   them and a redeploy never stomps a live toggle. Toggle by hand with
   `stow-admin maintenance on|off|status [--scope anonymous|lanes|all] --yes`:
   it dispatches `operations.yml`, which runs `stow-admin maintenance`
   with the repository's `CLOUDFLARE_API_TOKEN`, so no operator holds a
   WAF token and every toggle is recorded under the GitHub account that
   dispatched it.

### Billing notifications

The zone rule bounds request volume; usage-based billing notifications
watch the spend itself. In the Cloudflare dashboard (*Notifications →
Add → Billing → Usage Based Billing*) create an alert for each
billable metric the edge consumes — Workers requests and Durable
Object requests — with the alert threshold at $8/month; the
project budget is $10/month. See the
[Cloudflare notifications docs](https://developers.cloudflare.com/notifications/notification-available/)
for the alert type.

Per-metric alerts lag posted spend — #439 showed usage notifications
staying at 0% while cost accrued — so they are paired with an
account-wide budget alert: *Billing → Notifications → Budget Alerts →
Add budget alert*, a **spend** alert on the account at $8/month (and a
50% warning at $4). The budget alert meters whole-account invoiced
usage and catches metrics no per-service alert names. See the
[Cloudflare budget alerts docs](https://developers.cloudflare.com/billing/manage/budget-alerts/).
The #450 watchdog remains the outer circuit.

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
version overrides reach it, then
fires the synthetic suite through the same override — 250 requests on the
candidate interleaved with 250 on the baseline across the site, crate
lookup, artifact HEAD, stats and scheduler status paths, each with a
query string unique to the probe so the zone cache cannot answer it;
the verdict's `--min-requests-per-version` floor is 200 on each side,
below the suite count because Workers analytics is sampled — and
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
  read/written per DO request from `durableObjectsPeriodicGroups`.
  A breach here rolls back too.

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
  WAF step below and `stow-admin maintenance`/`watchdog` read it,
  `operations.yml` among them.
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
- `STOW_GITHUB_WEBHOOK_SECRET` → Worker `STOW_GITHUB_WEBHOOK_SECRET` —
  the HMAC key of the repository's `workflow_run` webhook (see GitHub
  webhook below); the repository secret and the webhook's secret hold
  the same value.

Deploying by hand (with the same environment variables exported) is
equivalent:

```sh
skyzen deploy --provider cloudflare --manifest edge/Skyzen.toml
```

## CI runner (GitHub Actions)

Trusted builds are `.github/workflows/build-crate.yml` on `main` of
`water-rs/stow`. The scheduler dispatches it with `workflow_dispatch`
(`ref: main`, one `task` input carrying the JSON `BuildTaskPayload`) —
one task is one run — and the workflow stays the signing identity;
the runner is picked from the task's target (`ubuntu-latest`,
`macos-14`, `windows-latest`). Add a target by extending the
`runs-on` map in `build-crate.yml`.

The workflow is two jobs and needs no edge URL: `build` compiles the
crate with `contents: read` only — no secrets, no OIDC — and uploads
its output directory as a workflow artifact. `publish` runs only when
`build` succeeds: it downloads the output, validates it against the
task and an independently resolved dependency closure, and only then
pushes the bundle plus the build's `Vec<ArtifactRecord>` (as one signed
OCI artifact tagged `records-<rustc>-<task_id hash>-<run_id>-<run_attempt>`,
one per task) to GHCR, cosign-signing both
(keyless, `id-token: write`). The job never calls the edge — GitHub's
`workflow_run` webhook delivery reports the outcome instead, and the
edge checks the records artifact each successful task published exists
in GHCR before it forwards the completion. See
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
`index-publish.yml` certificate identity). Its `report` dispatch input
(boolean, default `false`) is optional: when set, the job also reports
each slice's membership to the edge named by the `STOW_EDGE_URL`
repository variable (`POST /api/v1/admin/index/published`, the report
the scheduler's dependency gate reads) and prints the export report; when
unset — Cloudflare down or the edge unprovisioned — the publish still
lands. The dispatcher chooses whether to report, never where the run's
OIDC token goes; `index-publish-cron.yml` sets `report` whenever the
variable is configured. The remaining dispatch inputs shape the export pass
itself: `rustc_version` names the rustc it scopes to (empty resolves
the current stable channel), and `full` — per rustc, like the pass —
rebuilds that rustc's slices from every `records-<rustc>-*` artifact
while ignoring the published `index`/`folded` pairs entirely, so a
slice published in a format the current `stow-admin` can no longer
decode is replaced rather than read.

Every artifact is a tag of its rustc's GHCR package
`ghcr.io/water-rs/stow-cache-<rustc>` —
`{crate}.{version}-{target_short}-{rustc_short}-{feat_hash}-{c_metadata}{kind_suffix}`.
The edge pulls the package with no credential at all — public GHCR
packages grant `repository:water-rs/stow-cache-<rustc>:pull` to the
anonymous `GET /token` exchange that `edge/src/ghcr.rs` drives on every
`401` challenge. A rustc's package is created by the first
`build-crate.yml` push that lands on it: the package links to the
public `water-rs/stow` repository and inherits its visibility, so no
manual step ever opens one. Until it exists, GHCR answers an anonymous
pull — the token exchange or an asset request — with `403 DENIED`
rather than `404` (a package made private answers the same way), and
every index reader classifies that answer as the package's absence: the
empty index, exactly the result a missing `index.<target>.<rustc>` tag
gives (stow#844).

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

The route acts only on `build-crate.yml` and `resolve-request.yml` runs
on `main`, and forwards only the deliveries the scheduler consumes (see
`AGENTS.md`, Architecture). On a build run's `completed` it parses
`display_title` into the run's rustc and task id and forwards the run's outcome to the scheduler's
`POST /tasks/complete-run`. A `success` conclusion counts only once the
records artifact its publish job pushed (tagged by run id and attempt)
exists in GHCR, so a spoofed success cannot mint a catalog entry.

### newreleases.io webhook — `rust` releases

A new stable rustc wakes the preheat wave through newreleases.io's
release feed (stow#880), replacing the cron poll: subscribe a webhook
on the `rust-lang/rust` project in the newreleases.io settings, posting
to `https://stow.waterui.dev/api/v1/newreleases/release`, then copy the
webhook's signing key into the `STOW_NEWRELEASES_WEBHOOK_SECRET`
repository secret, which `deploy-edge.yml` uploads as the Worker secret
of the same name. Each delivery carries `X-Newreleases-Timestamp` and
`X-Newreleases-Signature` — the hex HMAC-SHA256 of
`<timestamp>.<body>` under that key — and the edge refuses anything
unsigned, stale (±300 s) or naming another project. A verified
`rust-lang/rust` release forwards its claimed version to the
scheduler, which dispatches `preheat-admin.yml` through the same
GitHub App arm the build dispatch uses; the workflow itself confirms
the version against `channel-rust-stable.toml` before resolving, so a
forged delivery costs one manifest check. A dispatch failure answers
502 and newreleases.io's retry redelivers.

## Trusted-endpoint authentication

Every authenticated endpoint — the whole `/api/v1/admin/*` surface
(queue reads and transitions, the dispatch freeze, the scheduler reset,
the demand lane, the index report, operator status) plus the
`/api/v1/scheduler/*` submit and outcome routes — takes
`Authorization: Bearer <credential>` and resolves the credential to a
GitHub identity (`edge/src/github_auth.rs`). Two shapes authenticate:

- **GitHub Actions OIDC JWT.** A workflow's per-run JWT
  (`audience=$STOW_OIDC_AUDIENCE`, minted per request by `stow-admin`).
  The edge verifies the RS256 signature against GitHub's JWKS
  (`token.actions.githubusercontent.com/.well-known/jwks`, fetched per
  call) and pins `iss`, `aud` (to the `STOW_OIDC_AUDIENCE` var),
  `repository` (to the `GITHUB_REPO` var), `exp`/`nbf`, and requires
  the `job_workflow_ref`, `workflow_ref`, `ref`, `run_attempt` and
  `actor` claims. Nothing is stored or rotated — a leaked run token
  dies with the run.
- **Repo-push credential.** Outside Actions, `stow-admin` sends the
  token `stow-admin login` stored: a `stow-ci` App user token from
  GitHub's device flow, bound to the operator's account and expiring
  after eight hours, kept in the OS credential store. A job or the local
  dev loop may stage `GH_TOKEN`/`GITHUB_TOKEN` instead; `stow-admin`
  never forwards `gh auth token` to the edge. The edge probes push capability directly — a GET on the repo's
  `git-receive-pack` ref advertisement answers 200 only when GitHub would
  accept a push from that credential — which works uniformly for user
  tokens, fine-grained PATs, and installation tokens. Access follows
  GitHub role changes — revoke by removing push access, nothing to
  rotate.

Both shapes read. **Only a workflow's OIDC token mutates**: each
mutating route names the workflow files that may call it, and admits a
token only when its `ref` is `refs/heads/main` and both its
`workflow_ref` and `job_workflow_ref` are one listed file at
`refs/heads/main` — a user token, another ref's copy of a listed
workflow, a listed workflow reached as a reusable workflow, and any
other workflow are refused with `401`. Every run is admitted on its
first attempt only: a re-run carries the original run's `actor`, so
admitting it would attribute one person's mutation to another. A failed
lane recovers by dispatching a fresh run, never by re-running jobs. The
lists live in `edge/src/api.rs` (the
`MutationPolicy` types):

| Routes | Workflows |
|---|---|
| `POST /api/v1/admin/dispatch-freeze`, `POST /api/v1/admin/queue/{retry,cancel,promote,purge}`, `POST /api/v1/admin/scheduler/reset`, the mock-only `POST /api/v1/admin/scheduler/budget[/seed,/rearm]` | `operations.yml` |
| `POST /api/v1/scheduler/tasks/submit` | `operations.yml`, `preheat-admin.yml`, `preheat-missed.yml` |
| `POST /api/v1/scheduler/tasks/submit-ids` | `operations.yml`, `preheat-admin.yml` |
| `POST /api/v1/admin/scheduler/demand`, `POST /api/v1/admin/scheduler/demand-feed/{query,begin,page,complete,cleanup,deliver}` | `operations.yml`, `demand-feed.yml` |
| `POST /api/v1/admin/index/published` | `index-publish.yml` |
| `POST /api/v1/scheduler/requests/{request_id}/outcome` | `resolve-request.yml` |

The verified `actor` — the login that started the run — is written into
the first scheduler log row each mutating request appends, and into the
manual dispatch-freeze record (`{"kind":"manual","actor":…}`, which the
freeze alert mail names). A scheduler reset has dropped every earlier row,
so it appends a `StoreReset` row first to carry the actor.

Upstream GitHub failures return `502 github trust upstream unavailable`
(so CI retries); every credential failure returns `401`. The trusted
caller — `actions:<job_workflow_ref> run <id> attempt <n> actor <login>`
or `push:<login>` — is recorded in the worker log on each write.

## Operator mutations

Operators are untrusted, and no credential on an operator's machine
mutates the edge: every mutation runs in `.github/workflows/operations.yml`
on `main`, so it leaves a GitHub Actions run under the dispatcher's
account. The run's OIDC token is the only credential the operator
routes above accept.

Setup (once per repository): under Settings → Environments create
`operations` and limit its deployment branches to `main` (*Deployment
branches and tags → Selected branches and tags*). The workflow's job runs
in that environment, so a run of any other ref cannot start. It reads the
repository variables `STOW_EDGE_URL`, `STOW_OIDC_AUDIENCE`,
`CF_ACCOUNT_ID` and `CF_ZONE_ID` and the secrets `CLOUDFLARE_API_TOKEN`
and `CF_ANALYTICS_TOKEN` (see the secrets above and
[`ENVIRONMENT.md`](ENVIRONMENT.md)), and each command sees only what its
class needs: `maintenance` and `watchdog` get the Cloudflare token, zone
and account; `preheat missed` gets the analytics token and account; the
rest get the edge URL and audience alone.

`stow-admin` dispatches the workflow for these mutating commands, each
under `--yes` where the command takes it: `scheduler reset`,
`scheduler demand-feed`, `queue retry|cancel|promote|purge`,
`dispatch-freeze engage|clear`, `submit`, `maintenance ensure|on|off|status`,
`watchdog` (not `--dry-run`), `preheat binary|top-binaries|missed|manual`
and `preheat projects submit`. It sends the argument list as a JSON array
the workflow replays without a shell, plus the contents of the files
`preheat manual` names with `--crates`, `--projects` and `--source-trees`;
`preheat manual --dirs` is refused, since the runner cannot see the
operator's directories. The command prints `operations.yml run: <url>` as
soon as GitHub creates the run, follows it every 10 seconds, and succeeds
only when the run concludes `success`; it gives up after 75 minutes (the
job's own limit is 60). Runs queue in one concurrency group, so mutations
never race, and the run name is `stow-admin <argv> (by <login>)`. The
tool comes from the signed toolchain of `main`'s head, the same pull
`watchdog.yml` makes.

What the operator needs:

- `STOW_EDGE_URL` set and not a loopback address — the workflow acts on
  the production edge whatever the variable says, so a command aimed at a
  local edge is refused before anything is dispatched.
- A `stow-admin login` token that carries Actions read and write, to
  dispatch the run and read its status.

Without `--yes` a command prints its plan locally and dispatches nothing.
Reads (`status`, `queue list`, `dispatch-freeze status`) call the edge
directly with the login token. Inside Actions, or with a minted OIDC JWT
in `GH_TOKEN` (the mock stack, [`MOCK.md`](MOCK.md)), a command calls
the edge directly instead of dispatching. The scheduled and dispatched
lanes (`preheat-admin.yml`, `preheat-missed.yml`, `demand-feed.yml`,
`index-publish.yml`, `resolve-request.yml`) call their own routes with
their own tokens.

## Initial cache population

The cache preheats itself — `preheat-cron.yml` dispatches a wave
daily, and the newreleases.io webhook wakes one on every new stable
rustc. To seed a wave by hand, `preheat manual` dispatches
`operations.yml` ([Operator mutations](#operator-mutations)), which
resolves the graph on the runner from the carried `--crates` /
`--projects` files and submits one dependency tree per source to the
scheduler's operations lane at the caller's `--priority` (stow#880 —
the scheduler owns dispatch from there, so it needs a reachable edge):

```sh
STOW_EDGE_URL=https://stow.waterui.dev stow-admin preheat manual \
    --crates crates.txt \          # one `name` or `name@version` per line
    --rustc-version 1.91.1 \
    --yes
```

The same command takes `--projects preheat/projects.toml` for a
repository list. It is resumable — the scheduler deduplicates on task
identity, so a re-run inserts only what is still missing — and exits
non-zero naming every `--projects` repository that failed to resolve.

The scheduler-driven lanes still work the same way when the edge is up —
from a machine that has `STOW_EDGE_URL` exported and is signed in with
`stow-admin login`:

```sh
stow-admin preheat top-binaries \
    --targets x86_64-unknown-linux-gnu,aarch64-apple-darwin \
    --rustc-version 1.91.1 --limit 100 --yes
```

Each invocation enqueues the resolved crate tasks and returns immediately. The
scheduler dispatches them to GitHub Actions in parallel as
`build-crate.yml` runs (subject to
`STOW_MAX_CONCURRENT_JOBS`, default 45 — runner slots, one per
in-flight run — the per-family
`STOW_MAX_CONCURRENT_MACOS_JOBS`, default 16, and
`STOW_DISPATCH_MIN_AGE_MINUTES`; failed dispatches retry with
exponential backoff, and a task's lease — renewed by each `status`
reconcile that lists its run queued or in progress — expires after
`STOW_STALE_DISPATCH_MINUTES`, default 60, returning the task to
pending for re-dispatch).




## Operating

- **Queue introspection:** `curl https://your-edge/api/v1/scheduler/status`
- **Under attack:** `stow-admin maintenance on --scope anonymous --yes`
  (dispatches `operations.yml`), watch the request graph, then
  `maintenance off --scope anonymous --yes`. The
  rule lives on the `waterui.dev` zone's `http_request_firewall_custom`
  phase — blocked requests never invoke the Worker — and the trusted CI
  endpoints keep working. `--scope lanes` sheds only the scheduler-backed
  lanes (bundle bytes keep serving); `--scope all` takes the whole
  hostname down. `stow-admin maintenance status` prints all three
  rules' state.
- **GHCR storage:** the whole cache is one
  `ghcr.io/water-rs/stow-cache-<rustc>` package per rustc (every
  artifact a tag); monitor disk via the GitHub UI.
- **Revoking trusted access:** there is no shared credential to rotate.
  A workflow's access to a mutating route is its entry in that route's
  policy in `edge/src/api.rs` — revoke by removing the entry or the
  workflow. An operator can mutate only by dispatching `operations.yml`,
  which needs write access to the repository: revoke on GitHub. Their
  read access is their repo push
  permission — revoke on GitHub, effective within
  `PUSH_VERDICT_TTL_SECS` (5 minutes): the edge caches the push-capable
  verdict per credential for that long rather than re-probing GitHub on
  every call, since the per-request probe is what shared Cloudflare
  egress got rate-limited. Denied verdicts expire sooner
  (`PUSH_DENIED_TTL_SECS`, 1 minute), and an isolate restart cold-starts
  the cache — so revocation can also land sooner, never later.

### Cache packages

The public cache is one GHCR package per rustc version:
`ghcr.io/water-rs/stow-cache-<rustc>` holds every artifact, bundle,
signature, records artifact, index slice and folded set built for that
rustc. A new rustc's package is created by the first `build-crate.yml`
push that lands on it — the package links to the public `water-rs/stow`
repository and inherits its visibility, so it is public with no manual
step. stow never deletes single versions; when a rustc is no longer
served, delete its package whole in the package settings, or through
GitHub support when one of its versions passed 5,000 downloads —
GitHub refuses self-service deletion then.

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