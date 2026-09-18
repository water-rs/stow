# Benchmark harness for `docs/acceleration-audit.md`

Reproduces the measurements end to end without Cloudflare. `edge_stub.py`
stands in for the edge worker, serving bundles out of a
`stow-mock-registry populate` output.

```
cargo build --release -p stow-cli -p stow-build -p stow-mock-registry
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out keys/mock.key
./pipeline.sh                      # clone -> capture -> populate -> benchmark -> purge
python3 report.py                  # render results.jsonl as a table
```

`pipeline.sh` processes one project at a time and purges its registry and
artifact cache afterwards, so peak disk stays flat regardless of list length.

- `capture.sh` runs the trusted CI builder against an existing checkout with
  `preserve_lockfile: true` and `features_json: ["default"]`, so the captured
  artifacts match what the user's own `cargo build` produces.
- `run_bench.sh` measures `cargo build`, `stow build`, `stow build
  --no-stow-resolver`, and the deps-prebuilt floor, each from a clean target
  directory.
- `projects.txt` is `name|version|git url|tag`.

Gotcha when comparing by hand: `stow build` adds `--remap-path-prefix` to
`RUSTFLAGS`, so a plain `cargo build` in the same `target/` recompiles
everything. `run_bench.sh` keeps them in separate target directories.
