# Deployment

This document describes how to deploy the production trust topology:

```
GitHub Actions ──register──► Edge Worker ──D1──► Cloudflare D1
     ▲                            │
     │ workflow_dispatch          ▼
     │                       GHCR (OCI)
     └──────── Scheduler DO ─┘
```

CI is the only producer of artifacts; the edge owns the D1 binding;
end users only ever talk to the edge. Detailed trust analysis lives in
[`ARCHITECTURE.md`](ARCHITECTURE.md#trust-boundaries).

## One-time Cloudflare setup

The production manifest is [`edge/Skyzen.toml`](../edge/Skyzen.toml). It
declares the `STOW_DB` D1 database, the `Scheduler` Durable Object with its
`v1` migration, the three runtime `[[secret]]` names (never values), the
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
   ```

   There are deliberately no shared scheduler/register secrets — the
   trusted endpoints authenticate GitHub identities instead (see
   [Trusted-endpoint authentication](#trusted-endpoint-authentication)).

3. Deploys run from GitHub Actions — see below. The first deploy also
   attaches the `stow.waterui.dev` custom domain (Cloudflare creates the
   DNS record in the `waterui.dev` zone automatically).

4. Rate-limit the edge API. `/api/v1/enqueue` and `/api/v1/requests` are
   the two endpoints an anonymous client can use to consume CI, and
   `/api/v1/catalog/graph` + `/api/v1/catalog/resolve-lockfile` fan a
   single call out to crates.io index fetches and D1 cache writes — but
   enumerating paths would leave the other anonymous routes (request and
   scheduler status, catalog lookups added later) unlimited, so the rule
   matches the `/api/v1/` path prefix and carves out only
   `/api/v1/artifacts/`. Artifact reads are excluded on purpose: a warm
   build fetches its closure at the CLI's prefetch concurrency and the
   per-`rustc` wrapper fetches on demand under cargo's own job
   parallelism, so one address legitimately sends tens of artifact
   requests per second, and a block there turns a cache hit into a
   local compile mid-build. That path is the cheap one — a Cache API hit
   costs one Worker request and no D1 or Durable Object work — and its
   volume is bounded by the DDoS managed ruleset, the billing
   notifications below, and the edge panic switch rather than by this
   rule. The Free plan allows exactly one rate-limiting rule, which is
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
     "description": "stow: per-IP limit on /api/v1/ except artifact reads",
     "expression": "starts_with(http.request.uri.path, \"/api/v1/\") and not starts_with(http.request.uri.path, \"/api/v1/artifacts/\")",
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
     "description": "stow: per-IP limit on /api/v1/ except artifact reads",
     "expression": "starts_with(http.request.uri.path, \"/api/v1/\") and not starts_with(http.request.uri.path, \"/api/v1/artifacts/\")",
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
   `/api/v1/artifacts/`, 60 requests per 10 seconds per IP, block for
   10 seconds.

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

`.github/workflows/deploy-edge.yml` runs `skyzen deploy --provider
cloudflare --manifest edge/Skyzen.toml` on every push to `main` that
touches the edge (`edge/`, `types/`, `shim/`, `Cargo.lock`) and on
`workflow_dispatch`. `skyzen deploy` resolves the declared `[[secret]]`
values from the job environment and delivers them through `wrangler
secret bulk`, so the Worker and its secrets move together.

Required GitHub Actions secrets:

- `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` — Wrangler
  authentication for the deploy itself.
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

The workflow is three jobs. `build` compiles the crate with
`contents: read` only — no secrets, no OIDC — and uploads its output
directory as a workflow artifact. `publish` runs only when `build`
succeeds: it downloads the output, validates it against the task and an
independently resolved dependency closure, and only then pushes to GHCR,
signs with cosign (keyless, `id-token: write`), registers with the edge,
and reports to the scheduler. `report-failure` runs when `build` does
not succeed — a bare `ubuntu-latest` job holding only `id-token: write`,
no checkout, no toolchain — and POSTs the failure report to the
scheduler directly. See
[`ARCHITECTURE.md`](ARCHITECTURE.md#trust-boundaries) for what the
publisher checks.

Repository configuration the `publish` and `report-failure` jobs read:

| Kind | Name | Value |
|---|---|---|
| variable | `STOW_EDGE_URL` | `https://stow.waterui.dev` |
| variable | `SCHEDULER_URL` | `https://stow.waterui.dev/api/v1/scheduler` |
| variable | `STOW_OIDC_AUDIENCE` | `https://stow.waterui.dev` — the `aud` the job requests when it mints its OIDC token; must equal the edge's `STOW_OIDC_AUDIENCE` var |

`GHCR_TOKEN` is the job's own `GITHUB_TOKEN` (`packages: write`), and
cosign signs with the job's OIDC identity, so the certificate subject is
`https://github.com/water-rs/stow/.github/workflows/build-crate.yml@refs/heads/main`
— the identity `stow_types::trusted_builder` pins and the CLI verifies.

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
requires. Minted tokens are cached in the Durable Object's SQL storage
and reused while more than five minutes of validity remain.

The crucial property: CI never holds a Cloudflare API token, and no
shared secret exists anywhere on the edge write surface — every trusted
call is a GitHub identity, verified as described below.

## Trusted-endpoint authentication

The three write endpoints — `POST /api/v1/admin/artifacts/register`,
`POST /api/v1/scheduler/tasks/submit`, and `POST /api/v1/scheduler/complete`
— take `Authorization: Bearer <credential>` and resolve the credential
to a GitHub identity (`edge/src/github_auth.rs`). Two shapes are
accepted:

- **GitHub Actions OIDC JWT.** The `publish` job of `build-crate.yml`
  already holds `id-token: write` for cosign; the same grant mints a
  per-run JWT (`ci/src/auth.rs` calls the `ACTIONS_ID_TOKEN_REQUEST_*`
  endpoint with `audience=$STOW_OIDC_AUDIENCE`), and the
  `report-failure` job mints one through the same endpoint for its
  `/complete` POST. The edge verifies the
  RS256 signature against GitHub's JWKS
  (`token.actions.githubusercontent.com/.well-known/jwks`, fetched per
  call) and pins `iss`, `aud` (to the `STOW_OIDC_AUDIENCE` var),
  `repository` (to the `GITHUB_REPO` var), `exp`/`nbf`, and
  `job_workflow_ref`. Register and `/complete` additionally require
  `job_workflow_ref` to be exactly
  `…/build-crate.yml@refs/heads/main` — the same identity the cosign
  signature pins; `tasks/submit` accepts any workflow running inside the
  trusted repo (that is how `preheat-admin.yml` calls it). Nothing is
  stored or rotated — a leaked run token dies with the run.
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

Once the edge is live, run the binary-derived overlay preheat from a
machine that has `STOW_EDGE_URL` exported and a GitHub credential with
push access to `water-rs/stow` — `GH_TOKEN`/`GITHUB_TOKEN`, or an
authenticated `gh` CLI (`gh auth login`):

```sh
stow-admin preheat-binary-overlay --target x86_64-unknown-linux-gnu \
    --rustc-version 1.91.1 --limit 100

stow-admin preheat-binary-overlay --target aarch64-apple-darwin \
    --rustc-version 1.91.1 --limit 100
```

Each invocation enqueues 100 build tasks and returns immediately. The
scheduler dispatches them to GitHub Actions in parallel (subject to
`STOW_MAX_CONCURRENT_JOBS`, default 45, the per-family
`STOW_MAX_CONCURRENT_MACOS_JOBS`, default 16, and
`STOW_DISPATCH_MIN_AGE_MINUTES`; failed dispatches retry with
exponential backoff and tasks stuck in `dispatched` for
`STOW_STALE_DISPATCH_MINUTES`, default 60, are re-queued).

For first-time bring-up, also run `preheat-t100` for the library base
pool. Library and binary overlays are independent.

## Operating

- **Queue introspection:** `curl https://your-edge/api/v1/scheduler/status`
- **Under attack:** `stow-admin panic on`, watch the request graph,
  `stow-admin panic off`. The flag lives in the scheduler Durable Object;
  while it is set every anonymous route answers `503` with
  `Retry-After: 300` and the trusted CI endpoints keep working.
  `stow-admin panic status` prints the current state.
- **D1 row count:** `wrangler d1 execute stow-prod --command "SELECT count(*) FROM artifacts"`
- **Rows without a published bundle:** `wrangler d1 execute stow-prod --command "SELECT count(*) FROM artifacts WHERE bundle_digest = ''"`.
  Such rows predate bundle publishing and are a miss until republished, so
  run the backfill right after the deploy that adds the column, from a
  machine with package write access:

  ```sh
  GHCR_USERNAME=<github user> GHCR_TOKEN=<PAT with write:packages> \
  STOW_EDGE_URL=https://stow.waterui.dev \
  stow-build backfill-bundles --batch 200
  ```

  The edge bearer is the developer's GitHub token (`GH_TOKEN`, else
  `gh auth token`), which must have push access to `water-rs/stow`.
- **GHCR storage:** the whole cache is the single `ghcr.io/water-rs/stow-cache`
  package (every artifact a tag); monitor disk via the GitHub UI.
- **Revoking trusted access:** there is no shared credential to rotate.
  CI access is the `build-crate.yml` OIDC identity itself — revoke by
  removing the workflow or narrowing the `job_workflow_ref` pin in
  `edge/src/github_auth.rs`. A user's access is their repo push
  permission — revoke on GitHub, effective on the next call.

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
   `<crate>-vX.Y.Z` (`stow-types-v*`, `stow-shim-v*`, `stow-cli-v*`);
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