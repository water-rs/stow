# Troubleshooting

Things stow says when something is wrong, and what they mean.

## The CLI talks to the wrong edge

Stow defaults to the production edge, `https://stow.waterui.dev`. To point
it at a mock or staging edge set `STOW_EDGE_URL` or `edge_url` in the
config file. Stow reads the file from
[`dirs::config_dir`](https://docs.rs/dirs/latest/dirs/fn.config_dir.html):

- macOS: `~/Library/Application Support/stow/config.toml`
- Linux: `~/.config/stow/config.toml` or `$XDG_CONFIG_HOME/stow/config.toml`

`~/.config` on macOS is **not** what stow reads. See [`CONFIG.md`](CONFIG.md).

## `warning: stow public cache is disabled for rustc <ver> because only the most recent two stable toolchains are supported`

You are running a `-nightly`, `-beta`, or `-dev` toolchain. The public
cache is keyed on rustc version, and stow refuses to attempt cache hits
for non-stable toolchains because they invalidate the cache key. Run
your benchmark on `rustup run stable stow check ...`.

## `direct dependency X cannot be satisfied from cached artifacts: no matching local semantic cache candidates`

This used to be a fatal error; modern stow logs a warning and falls
back to vanilla `cargo`. If you see the fatal form, you are on an old
binary — rebuild and reinstall. The underlying condition is "the
all-or-nothing top-crate fast path tried to engage but at least one
direct dep was not in the local artifact cache". Falling back to cargo
is the right behavior.

## `workspace dev profile enables LTO`

Every profile knob rustc sees (`opt-level`, `debug`, `debug-assertions`,
`overflow-checks`, `panic`, `strip`) is part of the compile identity, so a
workspace that tunes `[profile.dev]` or `[profile.dev.package."*"]` is
served whenever the pool holds artifacts built under that profile — which
is what project-source seeding produces for a project. The one setting no
identity expresses is `lto`: cargo then compiles every dependency with
`-C linker-plugin-lto`, so no unit can hit and stow runs plain cargo
instead of paying analysis overhead for guaranteed misses. Named-package
overrides (`[profile.dev.package.some-crate]`) never disqualify the
workspace. Set `lto = false` (or `"off"`) in the dev profile to opt back
in.

## `stow check` is slower than `cargo check`

On a populated cache, the inject path beats compilation; the worst
realistic warm path is roughly equal to vanilla warm. If you see a
slowdown:

1. Check `stow status` — look at `rust-cache: hits=N misses=M
   errors=E`. If hits is 0 and misses is high, the wrapper is finding no
   rows in the cached index slice. Causes:
   - The index has rows for your deps but the user's lockfile resolves
     to a different `dependency_c_metadata_json` than the cached
     standalone build. The fix is `stow-admin preheat binary-overlay`,
     which preserves the lockfile (see [`MOCK.md`](MOCK.md) and
     [`prebuild-pool-algorithm.md`](prebuild-pool-algorithm.md)).
   - The index has zero rows for your deps. Run `stow predict` to
     confirm; if the "index has rows for" line is 0, populate the
     cache first.
   - The slice was never fetched: `stow index status` shows whether a
     verified slice for your `(target, rustc)` is cached and
     `stow index refresh` pulls it. When the registry is unreachable
     the wrapper degrades to plain cargo — check `STOW_REGISTRY_BASE_URL`.
2. If errors > 0, the registry pull failed (auth, digest mismatch, or
   signature verification). Re-run with `RUST_LOG=stow_cli=debug` and look
   at the `bundle_digest` the warn line names.

## `path X is outside workspace root Y` on macOS

Resolved as of 2026-05-08 by canonicalizing both sides of the
`strip_prefix` check. If you still hit this, your `--manifest-path` and
the resolved workspace root point at different physical files (e.g.,
one through a bind mount). Use the canonical path on the command line:
`/private/tmp/...` instead of `/tmp/...`.

## Mock setup: `Failed to parse the key: Unsupported key type`

`stow-mock-registry populate` requires the cosign mock private key in
PKCS#8 PEM. macOS's default `openssl ec` writes SEC1; convert with:

```sh
openssl pkcs8 -topk8 -nocrypt -in private.pem -out private.pkcs8.pem
mv private.pkcs8.pem private.pem
```

## Mock setup: `Address already in use (127.0.0.1:8787)`

`skyzen dev` defaults Wrangler to port 8787. If you have another
service there (a `may rest --port 8787` process is the most common one
on this codebase), invoke wrangler manually with `--port 8788` and
point your CLI's `STOW_EDGE_URL` at the alternate port. See
[`MOCK.md`](MOCK.md).

## `wasm-bindgen` schema mismatch when running `skyzen dev`

`skyzen-cli` and the `wasm-bindgen` crate must report the **same**
0.2.x patch version. The two are versioned in lockstep upstream; pin
your `skyzen-cli` install to the version matching whatever
`wasm-bindgen` is locked to in stow's `Cargo.lock`:

```sh
cargo update -p wasm-bindgen
grep -A1 '"wasm-bindgen"' Cargo.lock | head -2
# Then in skyzen/cli/Cargo.toml:
# wasm-bindgen-cli-support = "=<that exact patch>"
cargo install --path /path/to/skyzen/cli --force
```

## `404 Not Found {"error":"Route not found."}` from the edge

You're hitting an endpoint the edge doesn't expose. Common cases:

- The wasm bundle on disk predates a recent route addition. Re-run
  `skyzen dev` to repackage the bundle.
- You typed the path wrong. The full route table is in
  [`ARCHITECTURE.md`](ARCHITECTURE.md#wire-protocol-surface-http).

## `401 Unauthorized` from `/api/v1/admin/artifacts/register`

The bearer credential did not resolve to a trusted GitHub identity. In
Actions, check the run minted its OIDC token for `aud = STOW_OIDC_AUDIENCE`
and ran on `water-rs/stow`'s `build-crate.yml`. Locally, the `GH_TOKEN`/
`gh auth token` owner must have push access to `water-rs/stow`. A
`502 github trust upstream unavailable` instead means the edge could not
reach GitHub — retry; it is not a credential problem.

## `400`/`403`/`409` from `/api/v1/admin/artifacts/register` after auth passes

The request is bound to the scheduler task `task_id` names. A `400` means
an Actions OIDC caller sent no `task_id` — CI gets it from
`STOW_BUILD_TASK_JSON`; a `409` means the task is unknown to the queue or
no longer in flight (only `dispatched`/`running` accept records — a
completed or stale-requeued task must be re-dispatched before re-registering);
a `403` means a record escaped the task's scope — its `target` or
`rustc_version` differs from the task's, or its `(crate, version)` is
outside the task's crates.io dependency closure. The error body names the
offending record.

## `"failed: 1"` lingering in `/api/v1/scheduler/status`

The scheduler queue persists across wrangler restarts when
`--persist-to` is set. A previous task that failed before completion is
still recorded. To start fresh: stop wrangler, `rm -rf
/tmp/stow-bench/edge-state`, restart.
