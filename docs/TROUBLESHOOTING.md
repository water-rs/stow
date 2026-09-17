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

## `workspace dev profile diverges from the public cache's canonical profile`

The trusted CI builds every artifact with cargo's default `dev` profile.
If your workspace root sets identity-relevant knobs — `[profile.dev]`
`opt-level`, `debug`, `strip`, `debug-assertions`, `overflow-checks`,
`panic`, `lto`, or a `[profile.dev.package."*"]` wildcard override — your
dependency artifacts can never byte-match the cache, so stow runs plain
cargo instead of paying analysis overhead for guaranteed misses. Neutral
knobs (`codegen-units`, `incremental`, `split-debuginfo`) and
named-package overrides (`[profile.dev.package.some-crate]`) do not
disqualify the workspace. Remove the divergent override to opt back in.

## `stow check` is slower than `cargo check`

On a populated cache, the inject path beats compilation; the worst
realistic warm path is roughly equal to vanilla warm. If you see a
slowdown:

1. Check `stow status` — look at `rust-cache: hits=N misses=M
   errors=E`. If hits is 0 and misses is high, the wrapper is doing
   round-trips to the edge that all miss. Causes:
   - The edge has rows for your deps but the user's lockfile resolves
     to a different `dependency_c_metadata_json` than the cached
     standalone build. The fix is `stow-admin preheat-binary-overlay`,
     which preserves the lockfile (see [`MOCK.md`](MOCK.md) and
     [`prebuild-pool-algorithm.md`](prebuild-pool-algorithm.md)).
   - The edge has zero rows for your deps. Run `stow predict` to
     confirm; if the "edge has rows for" line is 0, populate the
     cache first.
2. If errors > 0, the edge is unreachable or returning 5xx. Check
   `STOW_EDGE_URL` and try `curl $STOW_EDGE_URL/api/v1/scheduler/status`.

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

CI's `STOW_REGISTER_AUTH_TOKEN` does not match the edge's
`REGISTER_AUTH_TOKEN` binding. The compare is constant-time. Rotate
both halves to the same value.

## `"failed: 1"` lingering in `/api/v1/scheduler/status`

The scheduler queue persists across wrangler restarts when
`--persist-to` is set. A previous task that failed before completion is
still recorded. To start fresh: stop wrangler, `rm -rf
/tmp/stow-bench/edge-state`, restart.
