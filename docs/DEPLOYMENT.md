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
`v1` migration, the four runtime `[[secret]]` names (never values), the
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
   skyzen secret set SCHEDULER_AUTH_TOKEN  # cf-secret used by stow-admin
   skyzen secret set REGISTER_AUTH_TOKEN   # cf-secret used by trusted CI
   skyzen secret set GITHUB_APP_PRIVATE_KEY  # stow-ci GitHub App PEM; same key as the STOW_APP_PRIVATE_KEY repository secret
   skyzen secret set STOW_POW_CHALLENGE_SECRET  # HMAC key for enqueue-admission challenges
   ```

3. Deploys run from GitHub Actions — see below. The first deploy also
   attaches the `stow.waterui.dev` custom domain (Cloudflare creates the
   DNS record in the `waterui.dev` zone automatically).

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
- `STOW_SCHEDULER_AUTH_TOKEN` → Worker `SCHEDULER_AUTH_TOKEN`.
- `STOW_REGISTER_AUTH_TOKEN` → Worker `REGISTER_AUTH_TOKEN`.
- `STOW_APP_PRIVATE_KEY` → Worker `GITHUB_APP_PRIVATE_KEY` — the same
  GitHub App private key release-plz mints tokens from (see Releases
  below).
- `STOW_POW_CHALLENGE_SECRET` → Worker `STOW_POW_CHALLENGE_SECRET` —
  HMAC key for enqueue-admission challenges (any strong random string).

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

The workflow is two jobs. `build` compiles the crate with
`contents: read` only — no secrets, no OIDC — and uploads its output
directory as a workflow artifact. `publish` downloads it, validates it
against the task and an independently resolved dependency closure, and
only then pushes to GHCR, signs with cosign (keyless, `id-token: write`),
registers with the edge, and reports to the scheduler. See
[`ARCHITECTURE.md`](ARCHITECTURE.md#trust-boundaries) for what the
publisher checks.

Repository configuration the `publish` job reads:

| Kind | Name | Value |
|---|---|---|
| variable | `STOW_EDGE_URL` | `https://stow.waterui.dev` |
| variable | `SCHEDULER_URL` | `https://stow.waterui.dev/api/v1/scheduler` |
| secret | `STOW_REGISTER_AUTH_TOKEN` | same value as the edge `REGISTER_AUTH_TOKEN` binding |
| secret | `SCHEDULER_AUTH_TOKEN` | same value as the edge `SCHEDULER_AUTH_TOKEN` binding |

`GHCR_TOKEN` is the job's own `GITHUB_TOKEN` (`packages: write`), and
cosign signs with the job's OIDC identity, so the certificate subject is
`https://github.com/water-rs/stow/.github/workflows/build-crate.yml@refs/heads/main`
— the identity `stow_types::trusted_builder` pins and the CLI verifies.

The edge pulls these packages with no credential at all — public GHCR
packages grant `repository:<name>:pull` to the anonymous `GET /token`
exchange that `edge/src/ghcr.rs` drives on every `401` challenge. One
manual step remains after the first trusted build pushes
`ghcr.io/water-rs/stow-cache/<crate>`: set the package visibility to
public in the `water-rs` org package settings ([GitHub's package
visibility docs](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility)).
Until then the exchange fails with the `401`/`403` the `FetchError`
reports.

The edge authenticates `workflow_dispatch` with a GitHub App
installation token minted on the Worker: the `GITHUB_APP_ID`
(`4985635`) and `GITHUB_APP_INSTALLATION_ID` (`162649982`) vars plus
the `GITHUB_APP_PRIVATE_KEY` secret are used to sign an RS256 JWT
(WebCrypto) and exchange it at the GitHub API. The `stow-ci` App is
installed on `water-rs` (selected repositories: `water-rs/stow`) with
**Actions: Read and write**, which is the permission the dispatch call
requires. Minted tokens are cached in the Durable Object's SQL storage
and reused while more than five minutes of validity remain.

The crucial property: CI never holds a Cloudflare API token. The only
write path it has into D1 is the edge's
`/api/v1/admin/artifacts/register` endpoint, gated by
`x-stow-register-token`.

## Initial cache population

Once the edge is live, run the binary-derived overlay preheat from a
machine that has `STOW_EDGE_URL` and `SCHEDULER_AUTH_TOKEN`:

```sh
stow-admin preheat-binary-overlay --target x86_64-unknown-linux-gnu \
    --rustc-version 1.91.1 --limit 100

stow-admin preheat-binary-overlay --target aarch64-apple-darwin \
    --rustc-version 1.91.1 --limit 100
```

Each invocation enqueues 100 build tasks and returns immediately. The
scheduler dispatches them to GitHub Actions in parallel (subject to
`STOW_MAX_CONCURRENT_JOBS`, default 10, and
`STOW_DISPATCH_MIN_AGE_MINUTES`; failed dispatches retry with
exponential backoff and tasks stuck in `dispatched` for
`STOW_STALE_DISPATCH_MINUTES`, default 60, are re-queued).

For first-time bring-up, also run `preheat-t100` for the library base
pool. Library and binary overlays are independent.

## Operating

- **Queue introspection:** `curl https://your-edge/api/v1/scheduler/status`
- **D1 row count:** `wrangler d1 execute stow-prod --command "SELECT count(*) FROM artifacts"`
- **GHCR storage:** the cache uses GHCR's `ghcr.io/water-rs/stow-cache` namespace;
  monitor disk via the GitHub UI.
- **Rotating credentials:** `skyzen secret set REGISTER_AUTH_TOKEN`
  rotates the trusted-CI register secret. Update GitHub Actions secrets
  (`STOW_*`) in the same step so the next deploy doesn't roll it back.
  Brief register window outage is acceptable; CLI reads are unaffected
  (only `/api/v1/admin/*` requires the token).

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
   `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`,
   `x86_64-apple-darwin`, and `x86_64-pc-windows-msvc`, then creates the
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
