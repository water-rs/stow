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

1. Create a Workers project (`wrangler login` + `wrangler init`).
2. Create the D1 database:

   ```sh
   wrangler d1 create stow-prod
   ```

   Note the `database_id` it prints; copy into your `Skyzen.toml`
   (or `wrangler.toml`).

3. Create the scheduler Durable Object class binding:

   ```toml
   [[durable_objects.bindings]]
   name = "SCHEDULER"
   class_name = "Scheduler"

   [[migrations]]
   tag = "v1"
   new_sqlite_classes = ["Scheduler"]
   ```

4. Add secrets:

   ```sh
   wrangler secret put GHCR_TOKEN              # GHCR pull token (read:packages)
   wrangler secret put SCHEDULER_AUTH_TOKEN    # cf-secret used by stow-admin
   wrangler secret put REGISTER_AUTH_TOKEN     # cf-secret used by trusted CI
   wrangler secret put GITHUB_TOKEN            # fine-grained token with actions:write to trigger workflow_dispatch
   ```

5. Add `vars` for the non-secret tunables:

   ```toml
   [vars]
   GITHUB_REPO              = "water-rs/stow"
   STOW_DISPATCH_MIN_AGE_MINUTES = "5"
   ```

6. Deploy:

   ```sh
   skyzen deploy --provider cloudflare --manifest Skyzen.toml
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

The edge's `GITHUB_TOKEN` binding must be allowed to trigger
`workflow_dispatch` on the repository (a fine-grained token with
`actions: write`).

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
- **Rotating credentials:** `wrangler secret put REGISTER_AUTH_TOKEN`
  rotates the trusted-CI register secret. Update GitHub Actions secrets
  in the same step. Brief register window outage is acceptable; CLI
  reads are unaffected (only `/api/v1/admin/*` requires the token).

## What deploys do NOT include

- The CLI binary (`stow`) is distributed via crates.io / GitHub
  Releases, not via the edge.
- The local-CI dispatch endpoint and mock-registry are dev-only;
  production never runs them.
