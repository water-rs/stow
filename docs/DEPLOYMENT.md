# Deployment

This document describes how to deploy the production trust topology:

```
GitHub Actions ──records artifact (keyless-signed)─► GHCR (OCI)
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
   destroyed. The same run then refills them, so no other step follows
   the reset: once the reset succeeds, `operations.yml` runs
   `stow-admin index published-rustcs`, which probes every stable
   release `static.rust-lang.org/manifests.txt` lists for a published
   `stow-cache-v2-<rustc>` package through the registry's anonymous tag
   listing, then dispatches `index-publish.yml` on the run's own
   release tag with `report=true` for each rustc found (not `full`: a
   reset leaves the slices in GHCR as they were) and `preheat-cron.yml`
   on that tag with `refresh=true`, which submits the wave although a
   preheat run already succeeded that UTC day (the once-a-day check
   reads this workflow's successful runs across refs). A failed probe, dispatch or an empty enumeration fails the
   run, which the watchdog reports as `operations.failed`. A stored record
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

   The #450 watchdog trips one of them, chosen by what the breach
   costs: `scheduler lanes` when a Durable Object billed dimension
   (`cf.do.*`) or a build-pipeline signal breaches — bundle downloads and
   index routes keep serving — and `anonymous` when a Worker billed
   dimension (`cf.worker.*`) breaches; with several breaches the widest
   scope wins. Each billed dimension trips when its total over the
   current UTC calendar month passes 80% of its monthly allowance; the
   last hour at 200% and 300% of the hourly pace (levels set by the
   `STOW_WATCHDOG_HOURLY_ALERT_PERCENTS` repository variable) only
   alerts. Two liveness signals alert too: `pipeline.preheat_stale` (no
   successful `preheat-admin.yml` run for 26 hours, set by
   `STOW_WATCHDOG_PREHEAT_MAX_AGE_HOURS`) and `pipeline.builds_stalled`
   (dispatchable tasks and a free slot, yet no `build-crate.yml` run
   created for 2 hours, set by `STOW_WATCHDOG_BUILD_STALL_HOURS`). Two
   history signals alert as well: `operations.failed` (an
   `operations.yml` run concluded `failure`, `timed_out` or
   `startup_failure` since the previous watchdog
   run, or within `STOW_WATCHDOG_OPERATIONS_WINDOW_HOURS`, 1 hour by
   default; the incident names the run and its argv) and
   `watchdog.gap` (the previous watchdog run started 45 minutes or more
   ago, set by `STOW_WATCHDOG_RUN_GAP_HOURS`, so a missed periodic
   dispatch is reported after the fact).
   `stow-admin watchdog clear` is the single recovery step: it
   disables both scopes the watchdog can enable, re-enables the
   workflows the incident recorded, and only then lifts the
   scheduler's dispatch freeze if engaged (the lift runs a dispatch
   pass, which needs `build-crate.yml` enabled). If a workflow fails to
   re-enable the freeze stays engaged and the command exits non-zero;
   rerun it. `--dry-run` prints the plan.

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

`.github/workflows/deploy-edge.yml` deploys a release only. It has one
trigger, `workflow_dispatch` with `canary_share` (default `5`), and
`toolchain-publish.yml` is what dispatches it: that workflow runs on the
release tag push (`v<semver>`), publishes the signed toolchain for every
platform, and then dispatches `deploy-edge.yml` on the same tag. The
`prepare` job refuses any other ref, and a tag that is not
`v<workspace version>` at the commit it points to. The deployed commit is
the release PR's head commit — the certified commit plus the version bump
(see [Releases](#releases)) — so nothing merged to `main` after a
certification reaches the edge, and a push to `main` deploys nothing.

No job waits: the deploy is four jobs, and the observation windows are
GitHub environment wait timers, which hold no runner. Operator setup
(once per repository): under Settings → Environments create

- `deploy-canary` — wait timer `15` minutes (the canary observation
  window, the `canary-verdict` job's delay);
- `deploy-promoted` — wait timer `15` minutes (the `promoted-verdict`
  job's delay after promotion; the analytics datasets settle on the
  promoted DO workload window meanwhile).

Both environments limit their deployment branches and tags to release
tags: *Deployment branches and tags → Selected branches and tags*, one
tag rule, `v*`. The jobs run on the release tag the deploy was dispatched
on, which no branch rule admits.

Change a window by editing that environment's wait timer; the verdict
reads the window's bounds from timestamps, so nothing else moves.

The `prepare` job uploads the new Worker version without deploying it —
`skyzen deploy --upload-only` plans `wrangler versions upload`, and the
declared `[[secret]]` values travel in the same upload through
`--secrets-file` — then drives the baseline's Durable Object workload
(below), then adds it to the deployment at `0%` so that
version overrides reach it, then
fires the synthetic suite through the same override — 250 requests on the
candidate interleaved with 250 on the baseline across the site, crate
lookup, artifact HEAD, stats and scheduler status paths, each with a
query string unique to the probe so the zone cache cannot answer it;
the verdict's `--min-requests-per-version` floor is 200 on each side,
below the suite count because Workers analytics is sampled — and
finally shifts `canary_share`% of traffic onto it.

`wrangler versions upload` does not apply triggers, so the `promote` job
runs `wrangler triggers deploy` right after the candidate reaches `100%`,
with the wrangler config `prepare` generated (passed as an artifact):
that applies `[cloudflare.triggers] crons` and the custom domain route.
They apply to the whole Worker rather than to a version, which is why they
wait for promotion — earlier, the `scheduled` handler would fire on
whichever version Cloudflare routes during the canary. A change to a cron
or the route therefore takes effect only on a deploy that passes both
verdicts' gate up to promotion.

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
  `scriptVersion` — DO cpu and rows read/written from
  `durableObjectsPeriodicGroups` per DO request — compare two equal
  Durable Object workload windows. `scripts/deploy-do-workload.sh`
  requests `/api/v1/scheduler/status` twice a second
  (`STOW_DO_WORKLOAD_RPS`), once in `prepare` while the deployment is
  still the baseline alone and once in `promote` right after promotion;
  each window is the 3 whole minutes (`STOW_DO_WORKLOAD_MINUTES`) that
  open at least 60 s after the workload's first request, so the request
  that hydrates the object the version change reset falls outside it.
  Both datasets are summed over the same bounds; alarm and organic DO
  work land in both windows alike. Each window must carry at least
  `MIN_DO_SAMPLE_REQUESTS` (280 of the ~358 scheduled) DO requests:
  below it the verdict reports `insufficient sample` on every DO row
  and fails closed instead of comparing. The report prints each
  window's bounds, DO requests, DO cpu and rows. A breach here rolls
  back too.

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

Trusted builds are `.github/workflows/build-crate.yml` on a release tag
of `water-rs/stow`. The scheduler dispatches it with `workflow_dispatch`
(`ref: v<version>`, the deployed edge's own release tag, one `task` input
carrying the JSON `BuildTaskPayload`) — one task is one run — and the
workflow stays the signing identity;
the runner is picked from the task's target (`ubuntu-latest`,
`macos-26`, `windows-latest`). Add a target by extending the
`runs-on` map in `build-crate.yml`.

The workflow is two jobs and needs no edge URL: `build` compiles the
crate with `contents: read` only — no secrets, no OIDC — and uploads
its output directory as a workflow artifact. `publish` runs only when
`build` succeeds: it downloads the output, validates it against the
task and an independently resolved dependency closure, and only then
pushes bundles plus the build's `BuildRecords` to GHCR. The records contain
bundle entries and declarations of nonrelocatable proc macros, in one signed
OCI artifact tagged `records-<rustc>-<task_id hash>-<run_id>-<run_attempt>`.
Both are signed keyless in process — one Fulcio
certificate per validity window, one Rekor entry per signature, the
job's `id-token: write` identity — with every registry write held under
`STOW_GHCR_WRITES_PER_MINUTE` (see [`ENVIRONMENT.md`](ENVIRONMENT.md)). The job never calls the edge — GitHub's
`workflow_run` webhook delivery reports the outcome instead, and the
edge checks the records artifact each successful task published exists
in GHCR before it forwards the completion. See
[`ARCHITECTURE.md`](ARCHITECTURE.md#trust-boundaries) for what the
publisher checks.

Build-script executables are outputs of their owning crate node, keyed for
the host that runs them and reusable across target builds. Index format 7
keeps them separate from library nodes. A program whose compiler dep-info
records `CARGO_MANIFEST_DIR` is not published: its local cache entry includes
the source directory. For a proc macro, the signed records instead declare
the completed node; consumers compile the program locally and use its signed
identity to validate the dependency closure. Its library dependencies remain
cached. Records use `application/vnd.stow.records.v2+json`; the deployment
uses a fresh `stow-cache-v2-<rustc>` package for this schema. Publish empty
index slices there with `index-publish.yml` and `report=false`. Set the new
package's visibility to public before resetting the scheduler and submitting
a new preheat wave. Readers and writers use only this namespace; old packages are retired
separately and never used as a fallback.

`build-crate.yml` reads no repository variables — `run-name` carries
`<rustc>-<task_id>` so the webhook's `display_title` parses back into
the run's rustc and task id.

`GHCR_TOKEN` is the job's own `GITHUB_TOKEN` (`packages: write`), and
the publish stage signs with the job's OIDC identity, so the certificate subject is
`https://github.com/water-rs/stow/.github/workflows/build-crate.yml@refs/tags/v<MAJOR.MINOR.PATCH>`
— the identity `stow_types::trusted_builder` pins and the CLI verifies:
the workflow file's exact URL, a `refs/tags/v` ref and a strict three-part
version, never a branch, a pre-release tag or another crate's tag. Only the
release workflow can create such a tag (a ruleset protects `refs/tags/v*`,
see [Release tag protection](#release-tag-protection)), so a signature under
it means the commit the tag points to went through the release flow.

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
`ghcr.io/water-rs/stow-cache-v2-<rustc>` —
`{crate}.{version}-{target_short}-{rustc_short}-{feat_hash}-{c_metadata}{kind_suffix}`.
The edge pulls the package with no credential at all — public GHCR
packages grant `repository:water-rs/stow-cache-v2-<rustc>:pull` to the
anonymous `GET /token` exchange that `edge/src/ghcr.rs` drives on every
`401` challenge. The first push creates a private package linked to
`water-rs/stow`. It inherits repository access permissions, not visibility;
set the package to public before anonymous pulls can succeed. Until it exists, GHCR answers an anonymous
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

### Periodic workflows — the edge Cron Trigger

GitHub's `schedule` trigger is best-effort and skipped most ticks
(`watchdog.yml` ran 5 of 96 expected times in a day, stow#1100), so the
edge Worker's Cloudflare Cron Trigger dispatches the periodic
workflows, which carry no `schedule`, through the GitHub App arm the
build dispatch uses (stow#1121 moved the last of them over). `edge/Skyzen.toml` declares the cadences in
`[cloudflare.triggers] crons` and the `STOW_PERIODIC_WORKFLOWS` var maps each
cron expression to the workflow entries due when it fires. All UTC:

| Cron | Workflow |
| --- | --- |
| `*/15 * * * *` | `watchdog.yml` |
| `17 0 * * *` | `preheat-cron.yml` |
| `*/10 * * * *` | `index-publish-cron.yml` (also runs on `workflow_run`) |
| `5 * * * *` | `demand-feed.yml` |
| `0 13 * * *` | `build-failure-digest.yml` |
| `0 7 * * *` | `release-gate.yml` (the nightly certification: on the release tag it only runs the trampoline job, which dispatches the certification on `main` with `nightly=true` and `test.yml` on `main`; see [Releases](#releases)) |
| `30 5 * * 1` | `preheat-projects.yml` (it checks out `main` and its PR opens against `main`) |
| `0 6 * * 1` | `preheat-missed.yml` |

An entry is a bare file name, dispatched on the deployed edge's own
release tag (`v<version>`, the workspace version the Worker was built
with); a periodic entry names no ref, and the production workflows run
the code of the release the edge was built from. The Worker's
`scheduled` handler looks the
event's cron up in that map and posts one `workflow_dispatch` per due
workflow through the scheduler object (`POST /periodic/dispatch`),
concurrently under a bound of four. To change a cadence, edit the cron
in both places; `admin/tests/periodic_schedule.rs` keeps the two
sets equal. Each workflow keeps `workflow_dispatch` for manual runs. The dispatch
carries no inputs, so a workflow's input defaults apply.

A failed dispatch (or a tick whose cron the map does not name) is logged,
mailed from `alerts@stow.waterui.dev` through the same `send_email`
binding as the freeze alerts, and fails the invocation in Workers Logs.
The edge cannot open the `incident` issue (the App carries no `issues`
grant), and the next tick retries. While the watchdog's breaker has
`preheat-cron.yml` disabled, that tick's dispatch is refused and mailed.

Cost: one Worker invocation per fired cron, and per due workflow one
scheduler-object request, at most one token mint and one dispatch POST.
Workflows a day: 96 watchdog, 144 index-publish-cron, 24 demand-feed, 1
each of preheat-cron, build-failure-digest, test and release-gate, plus two a week —
268 a day, so at most 536 subrequests a day, about 8,100 Worker requests
and 8,100 object requests a month (0.08% of 10M and 0.8% of 1M included),
and no stored rows. The eight distinct cron expressions sit far under
the Workers Paid account allowance of 250 Cron Triggers
(<https://developers.cloudflare.com/workers/platform/limits/>, "Number of
Cron Triggers per account"). The `POST /periodic/dispatch` drive in
`edge/src/scheduler/drives.rs` pins the zero-row budget.

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
dispatched on a release tag (`head_branch` is `v<MAJOR.MINOR.PATCH>`; any
release tag, since a run the previous release dispatched still completes
after a deploy), and forwards only the deliveries the scheduler consumes (see
`AGENTS.md`, Architecture). On a build run's `completed` it parses
`display_title` into the run's rustc and task id and forwards the run's outcome to the scheduler's
`POST /tasks/complete-run`. A `success` conclusion counts only once the
records artifact its publish job pushed (tagged by run id and attempt)
exists in GHCR, so a spoofed success cannot mint a catalog entry.

Failed completions carry the run id and attempt. The scheduler checks the
attempt's `verify source failure` job before excluding an independently
reproduced source failure from breaker counts. The failed build remains in
history; unverified failures and verification lookup errors still count.
The replay uses the original toolchain, manifest, lockfile and flags without
stow cache artifacts. It runs only after a candidate source failure, so its
additional compilation cost is confined to those failed builds. This does
not clear an existing freeze: after addressing its cause, use
`stow-admin watchdog clear`.

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
  (`token.actions.githubusercontent.com/.well-known/jwks`, held in
  isolate memory for an hour and refetched on an unknown `kid`) and pins `iss`, `aud` (to the `STOW_OIDC_AUDIENCE` var),
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
token only when its `ref` is `refs/tags/<the edge's own release tag>` and
both its `workflow_ref` and `job_workflow_ref` are one listed file at that
tag — a user token, another ref's copy of a listed workflow (a branch, or
another release's tag), a listed workflow reached as a reusable workflow,
and any other workflow are refused with `401`. A new deploy therefore
changes what the edge admits: runs of the previous release's tag stop
mutating when the new release is promoted. Every run is admitted on its
first attempt only: a re-run carries the original run's `actor`, so
admitting it would attribute one person's mutation to another. A failed
lane recovers by dispatching a fresh run, never by re-running jobs. The
lists live in `edge/src/api.rs` (the
`MutationPolicy` types):

| Routes | Workflows |
|---|---|
| `POST /api/v1/admin/dispatch-freeze`, `POST /api/v1/admin/dispatch-cap`, `POST /api/v1/admin/queue/{retry,cancel,promote,purge}`, `POST /api/v1/admin/scheduler/reset`, the mock-only `POST /api/v1/admin/scheduler/budget[/seed,/rearm]` | `operations.yml` |
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
on the deployed edge's release tag, so it leaves a GitHub Actions run under
the dispatcher's account. `stow-admin` reads that tag from the `release_tag`
field of the scheduler status the edge serves
(`GET /api/v1/scheduler/status`) and dispatches on it. The run's OIDC token is the only credential the operator
routes above accept.

Setup (once per repository): under Settings → Environments create
`operations` and limit its deployment branches and tags to release tags
(*Deployment branches and tags → Selected branches and tags*, one tag
rule, `v*`). The workflow's job runs in that environment, so a run of a
branch cannot start. It reads the
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
`dispatch-freeze engage|clear`, `dispatch-cap set`, `submit`,
`maintenance ensure|on|off|status`,
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
tool comes from the signed toolchain published for the run's own commit
(the release's), the same pull `watchdog.yml` makes.

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

### Repack follow-up

A repack sweep (`repack.yml` dispatched with `repack_rustc`, run title
`<rustc>-repack`; see *OCI bundle layout* in `ARCHITECTURE.md`) is
resumable, and its `repack` job, `build-crate.yml`'s called by `repack.yml`
so that it signs under that file's identity, is bound by GitHub's
350-minute job limit.
`repack-followup.yml` runs on the completion of every `repack` run
(a `build-crate` run creates none) and acts on a `<rustc>-repack` title, dispatching onto the release tag the completed run ran on with a
GitHub App installation token (`STOW_APP_ID` / `STOW_APP_PRIVATE_KEY`,
minted with `actions: write` only, as in `release-plz.yml`). The run's own
`GITHUB_TOKEN` is not used: GitHub documents that "events triggered by the
`GITHUB_TOKEN` will not create a new workflow run", so the completion of a
run dispatched with it would never trigger the follow-up again and the
chain would stop after one hop. Its jobs match the triggering workflow on
the run's `path`, not its `name`, which is the run-name (`<rustc>-repack`)
for `repack.yml`:

- Success: `index-publish.yml` for that rustc with `report=true` (the
  fold), then `preheat-cron.yml` with `refresh=true`.
- Retry of the parked nodes: on every successful `Index publish`
  completion the same workflow looks at the `<rustc>-repack` runs of the
  last 24 hours and, for each rustc whose newest repack run succeeded,
  dispatches `operations.yml` with
  `["queue","retry","--status","failed","--rustc","<rustc>","--yes"]`
  (returning the nodes parked `failed` by builds against old-layout
  bundles to `pending`) only when the index publish was created after
  that repack run completed, so its fold covers the repacked records, and
  no `operations.yml` run titled with that argv was created since the
  repack completed. The second condition is the one-shot marker: a node
  that keeps failing is not retried on every later publish. The retry
  follows a fold instead of the preheat dispatch because a retried node
  carries no backoff and is dispatched at once. The `Index publish` it
  chains on is the one the success branch above dispatches with the App
  token, so its completion reaches the workflow; a publish dispatched by
  `index-publish-cron.yml` with its `GITHUB_TOKEN` emits no such event.
- `failure` or `timed_out`: the sweep is dispatched again with
  `repack_rustc` and `repack_concurrency` from `STOW_REPACK_CONCURRENCY`
  (default 32). A `cancelled` run resumes only when its `repack` job
  (`repack / repack <rustc>` in the run's jobs API) is `timed_out`, or `cancelled` after
  running to within 15 minutes of its 350-minute limit: GitHub's REST
  documentation lists `timed_out` and `cancelled` as job conclusions
  without saying which a `timeout-minutes` expiry reports, so both are
  handled, and an operator cancel (a `cancelled` job well under the
  limit) is never resumed. No resume starts while another `<rustc>-repack`
  run is queued or running.
- Bound: with `STOW_REPACK_MAX_RUNS_PER_DAY` (default 8) or more
  `<rustc>-repack` runs created in the last 24 hours, the follow-up job
  fails with that message instead of dispatching; the run list and the
  watchdog's failure path show a sweep that does not converge.

## Initial cache population

The cache preheats itself — `preheat-cron.yml` dispatches a wave
daily (the edge's Cron Trigger fires it at 00:17 UTC;
[Periodic workflows](#periodic-workflows--the-edge-cron-trigger)), and the newreleases.io webhook wakes one on every new stable
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
`STOW_MAX_CONCURRENT_MACOS_JOBS`, default 11, and
`STOW_DISPATCH_MIN_AGE_MINUTES`; an operator's
`stow-admin dispatch-cap set --jobs N [--macos M]` replaces the two
cap bindings at claim time until the next `set` — the setting lives
in the scheduler's log, so it survives restarts and redeploys, there
is no clear, and a lowered cap cancels nothing already running
(stow#1039); failed dispatches retry with
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
  `ghcr.io/water-rs/stow-cache-v2-<rustc>` package per rustc (every
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

The public cache is one GHCR package per storage schema and rustc version:
`ghcr.io/water-rs/stow-cache-v2-<rustc>` holds every artifact, bundle,
signature, records artifact, index slice and folded set built for that
rustc. The first push creates the package with private visibility.
Repository access permissions are inherited separately. In the package's
GitHub settings, use **Danger Zone → Change visibility → Public** and confirm
the package name before opening the lanes. This applies to every new schema
or rustc package; making a package public cannot be reversed. See GitHub's
[package visibility documentation](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility#configuring-visibility-of-packages-for-an-organization). stow never deletes single versions; when a rustc is no longer
served, delete its package whole in the package settings, or through
GitHub support when one of its versions passed 5,000 downloads —
GitHub refuses self-service deletion then.

## Releases

`stow-cli` ships prebuilt binaries via
[cargo-dist](https://axodotdev.github.io/cargo-dist/book/); the
configuration lives in `dist-workspace.toml` and only the `stow-cli`
package is distributed (the other binary crates are internal tooling).

A release is a certified commit plus its version bump, and nothing else
ships. The flow:

1. **Certification.** `release-gate.yml` runs only by dispatch. The
   nightly is the edge's Cron Trigger (`0 7 * * *` UTC): it dispatches the
   workflow on the edge's release tag, where only the `trampoline` job
   runs — it dispatches `release-gate.yml` on `main` with `nightly=true`
   and `test.yml` on `main` (which keeps the caches saved from `main`'s ref
   fresh). A day-time release is certified by name:

   ```sh
   gh workflow run release-gate.yml --ref main -f sha=<commit>
   ```

   (an empty `sha` certifies `main`'s head). Every leg runs on the named
   commit: the mock end-to-end, the release flow (below), the traffic-cost
   and preheat-cost tests, the production wave and the monthly projection,
   and `Release gate` joins them. A failed nightly files or updates the
   `nightly` issue and opens nothing; a pass closes it.
2. **Release PR.** A passed gate runs the `release-pr` job, which runs
   `scripts/release-pr.sh <sha>`: the certified commit X is checked out as
   `main`, `release-plz release-pr` opens the release PR from it with the
   App's token — its head H is X plus the version bump and changelog, one
   commit, against `main` — and then the `Certified` commit status is set
   on X with the run's own `GITHUB_TOKEN`, so its creator is
   `github-actions[bot]`.
3. **Release.** Merging the release PR (a merge commit; `main` takes no
   other kind) pushes to `main` and starts `release-plz.yml`. Its
   `release` job runs `scripts/release-resolve.sh` on the pushed commit,
   which finds the merged PR from a `release-plz-*` branch opened by the
   App and takes its head H — never the merge commit, so commits merged to
   `main` after the certification are not in the release. It fails the job
   unless the merge's second parent is H, H has exactly one parent X, and X
   carries a `Certified` success status created by `github-actions[bot]`;
   a push that merges no release PR releases nothing. The job then checks
   out H and runs `release-plz release`: every crate whose version is not
   yet on crates.io is published over OIDC trusted publishing and tagged at
   H with the release App's token. The `stow-cli` tag is `v<version>`; the
   other crates' are `oci/v<version>`, `shim/v<version>` and
   `types/v<version>`, which no workflow triggers on. The crates.io trusted
   publisher entry of each published crate names `release-plz.yml`; leave
   its environment empty or `release`.
4. **Everything else runs from the tag `v<version>`.** Its push triggers
   `release.yml` (cargo-dist), which builds `stow-cli` for
   `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
   `aarch64-apple-darwin`, and `x86_64-pc-windows-msvc`, then creates the
   GitHub Release and attaches the archives, the shell and PowerShell
   installers, and `sha256` checksums; and `toolchain-publish.yml`, which
   publishes the signed toolchain for H and then dispatches
   `deploy-edge.yml` on the tag (see
   [Automated deploys](#automated-deploys)). The deployed edge dispatches
   every production workflow on that tag, and the builder and index
   workflows sign under it.

`scripts/release-flow-e2e.sh` runs steps 2 and 3 on the mock stack
(`MOCK.md`) as the release gate's `release-flow` leg, so a change to
release-plz, to either script or to the mock that breaks the flow fails
the certification before the release it would have gated. Until `dev` is
retired (stow#1516), `pr-base-gate.yml` admits `release-plz-*` branches
into `main` besides `dev`.

Required GitHub App configuration — two Apps, so the identity that can
open a release PR is not the one that can create a release tag:

| Kind | Name | Value |
|---|---|---|
| variable | `STOW_APP_ID` | the GitHub App's ID — opens the release PR |
| secret | `STOW_APP_PRIVATE_KEY` | that App's private key (PEM) |
| variable of the `release` environment | `STOW_RELEASE_APP_ID` | the release App's ID — creates the release tags |
| secret of the `release` environment | `STOW_RELEASE_APP_PRIVATE_KEY` | the release App's private key (PEM) |

The first App is installed on `water-rs/stow` with **Contents: Read and
write** and **Pull requests: Read and write** (plus **Actions: Read and
write**, which the scheduler uses — see issue #33). The release App is a
separate App installed on `water-rs/stow` with **Contents: Read and write**
only: it is the one identity the tag ruleset below lets create `v*`
tags.

The `release-pr` job (in `release-gate.yml`) mints an installation token
for the first App and uses it for checkout and release-plz rather than the
default `GITHUB_TOKEN`: pull requests opened with `GITHUB_TOKEN` never
trigger other workflows, so the release PR's checks would never run; the
App token does trigger them, and it expires in an hour. The `release` job
of `release-plz.yml` mints a token for the release App for the same reason
on the tag: a tag pushed with `GITHUB_TOKEN` starts no run, so the
cargo-dist, toolchain and deploy runs would never start; a tag created
with an App token does start them. release-plz creates the tag but not the
GitHub Release (`git_release_enable = false` in `release-plz.toml`) —
cargo-dist owns the release so it can attach the artifacts.

### Release tag protection

The release tags are the root of trust: a signature under
`…@refs/tags/v<MAJOR.MINOR.PATCH>` is accepted by every reader, and the
edge dispatches production workflows on, and admits mutations from, its own
tag. Operator setup (once per repository), under Settings:

- **Environment `release`** — *Deployment branches and tags → Selected
  branches and tags*, one branch rule, `main`. It holds
  `STOW_RELEASE_APP_ID` and `STOW_RELEASE_APP_PRIVATE_KEY` (above), so the
  release App's key is readable by no run of any other ref. Only the
  `release` job of `release-plz.yml` uses it.
- **Tag ruleset** — Rules → Rulesets → *New tag ruleset*, enforcement
  *Active*, target `refs/tags/v*` (include pattern `v*`), rules *Restrict
  creations*, *Restrict updates* and *Restrict deletions*. The bypass list
  holds the release App and nothing else, *Always*: no person, role or
  other App can create, move or delete a release tag, and a release tag
  is therefore only ever created by a job that passed `release-resolve.sh`.
- **Environments `operations`, `deploy-canary` and `deploy-promoted`** —
  limited to release tags: *Selected branches and tags*, one tag rule,
  `v*` (see [Operator mutations](#operator-mutations) and
  [Automated deploys](#automated-deploys)). `deploy-canary` and
  `deploy-promoted` are created with their wait timers; `operations` is
  created as before, with this deployment rule.
- **The `main` ruleset** requires the checks `PR source gate`, `CI gate`
  and `installable release`. `Release gate` and `toolchain gate` are not
  required: certification is the dispatched `release-gate.yml`, and the
  toolchain is published by the tag's `toolchain-publish.yml`, so a merge
  to `main` waits for neither.

### The switching release and the one-time re-sign

The release that first signs under a release tag is a migration: records,
nodes and index slices published before it carry the
`…@refs/heads/main` identity, which readers no longer accept, so a CLI of
this release serves nothing from them until they are re-signed (CLIs
released earlier trust only the old identity and stop hitting the cache).
The operator's procedure, in order:

1. Complete the setup above: the release App, the `release` environment,
   the tag ruleset, the environment tag rules and the `main` ruleset
   change.
2. Engage the dispatch freeze, so the old edge dispatches no builds that
   would sign under `refs/heads/main` during the switch:

   ```sh
   stow-admin dispatch-freeze engage --yes
   ```

3. Merge the code onto `main`, then certify and release its head:

   ```sh
   gh workflow run release-gate.yml --ref main -f sha=<main head>
   ```

   The gate opens the release PR; merging it tags `v<version>`, which
   starts cargo-dist, the toolchain publish and the edge deploy.
4. When the deploy has promoted, re-sign each rustc whose repository holds
   records signed before the switch (`stow-admin index published-rustcs`
   lists them), on the new tag. For each rustc, first the records and
   nodes, then the index slices:

   ```sh
   gh workflow run resign.yml --ref v<version> -f rustc=<rustc> -f concurrency=<n>
   gh workflow run index-publish.yml --ref v<version> \
       -f rustc_version=<rustc> -f resign=true -f report=true
   ```

   `resign.yml` runs `stow-build resign` inside `build-crate.yml`'s job
   (so the signature's identity is `build-crate.yml` on the tag): every
   tag of the rustc's package is classified first and an unknown tag fails
   the run before anything is written; each records artifact and `built-`
   marker is re-signed in place, every task's live nodes are republished
   with a bundle carrying the new signature (the bundle digest changes), and
   one new records artifact per changed task carries the new rows.
   `index-publish.yml` with `resign: true` runs `stow-admin index resign`,
   which signs each `index.*` and `folded.*` slice under the new identity at
   the same digest, and then the normal export folds the new records.
   `concurrency` bounds the tasks re-signed at once; choose it from the
   rustc's record count and the Sigstore public-good instance's rate limits
   (the registry side is bounded by `STOW_GHCR_WRITES_PER_MINUTE`). Both
   runs verify under the old identity before signing and are rerun-safe: a
   rerun skips what already verifies under the new one, so an interrupted
   or rate-limited run is dispatched again unchanged.
5. Clear the freeze (`stow-admin dispatch-freeze clear --yes`) once every
   rustc's runs have finished, and record the runs' counts on stow#1515
   (`stow-build resign` prints the sweep's counts as JSON).
   `resign.yml`, `stow-build resign` and `stow-admin index resign` are
   removed by the following release (stow#1517).

## What deploys do NOT include

- The CLI binary (`stow`) is distributed via crates.io / GitHub
  Releases, not via the edge.
- The local-CI dispatch endpoint and mock-registry are dev-only;
  production never runs them.
