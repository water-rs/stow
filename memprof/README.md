# Resolve memory harness (local only — never merge)

Measures the edge resolve path's memory: a counting global allocator
(`resolve/src/util/alloc_profile.rs`) with per-phase marks and optional
per-category tags, an unauthenticated `/api/v1/debug/resolve/{project,crate}`
route (edge feature `mem-profile`, on by default in this patch), V8 heap
sampling through the inspector, and a native `resolve-memprof` binary for
dhat attribution on the same chain.

The harness commits apply on `origin/dev` and on top of the production series
(cherry-pick them after the commits being measured).

## Prerequisites
- node + wrangler in `~/node/bin`, `skyzen` in `~/.cargo/bin`, `jq`/`bc`/`python3`.
- Outbound network to github.com, codeload.github.com, index.crates.io, static.crates.io.
- `$MEMPROF_DIR` (default `~/memprof`) holds builds, `runs/`, `out/`, `dumps/`.

## Wasm (workerd) runs
```sh
memprof/build_copy.sh /path/to/stow-worktree mybuild   # release wasm build snapshot
memprof/suite.sh mybuild r1 emit                       # zed@1 target, bat@9, rust-analyzer@9
```
Each run starts a fresh `wrangler dev --local` isolate and reports, per input:
- `http … wall_s … workerd_cpu_ms` — workerd user+sys CPU across the request;
- the V8 summary (`used_peak`, `backing_peak` = ArrayBuffer backing stores,
  `used_plus_backing_peak`, MiB) sampled every 250 ms over the inspector;
- `global peak live … memory_size at peak … final memory_size …` from the
  counting allocator's last mark (`memory_size` is wasm linear memory);
- `MEMPROF_UNITS <target> <bytes> <blake3>` — the hash of
  `serde_json::to_string(&(units, roots))` per target (`emit`, `downloads=424242`).
  With `dump` (`downloads=424243`) the full JSON is also written to
  `dumps/<input>-<suffix>/<target>.json`; `cmp_dumps.py dirA dirB` compares two dumps.

Per-mark tables: `python3 memprof/summarize.py $MEMPROF_DIR/runs/zed-r1-wrangler.log`.

Per-category tags (`source`, `workspace`, `index_http`, `index_summary`,
`query`, `resolver`, `crate_dl`, `unpack`, `manifest`, `vfs`, …): build with
`default = ["mem-profile-tags"]` in `edge/Cargo.toml`; `summarize.py` then
prints live bytes per tag at the global peak (`at_peak`), each tag's own
peak, and its end-of-request live bytes.

## Native dhat runs
```sh
cargo build --release -p stow-resolve --features dhat-heap --bin resolve-memprof       # dhat
cargo build --release -p stow-resolve --features harness,mem-profile --bin resolve-memprof  # counting
# record fixtures once, then replay:
target/release/resolve-memprof zed-industries/zed 933d8d93819c749a607e561883855a9b95c79cea x86_64-unknown-linux-gnu --record $MEMPROF_DIR/zed-fixture
memprof/native.sh target/release/resolve-memprof n1
python3 memprof/dhat_top.py dhat-heap.json 3 15   # top sites (3 stow frames) by live-at-peak and by total
```
`native.sh` replays zed@1, bat@9 (git ref 979ba226…, v0.26.1) and
rust-analyzer@9 and writes each target's serialized `(units, roots)` to
`out/<input>-<suffix>.tsv` for `cmp`.
