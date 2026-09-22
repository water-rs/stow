# Benchmark harness for `docs/acceleration-audit.md`

Reproduces the measurements end to end without Cloudflare. There is no
edge stand-in: the CLI resolves artifacts from the signed local index and
the bench serves bundle bytes from the mock registry, so `stow-mock-registry` is
the only service the lane needs.

```
cargo build --release -p stow-cli -p stow-build -p stow-mock-registry
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out keys/mock.key
./pipeline.sh                      # clone -> capture -> populate -> index -> benchmark -> purge
python3 report.py                  # render results.jsonl as a table
```

`pipeline.sh` processes one project at a time and purges its registry and
artifact cache afterwards, so peak disk stays flat regardless of list length.

- `capture.sh` runs the trusted CI builder against an existing checkout with
  `preserve_lockfile: true` and `features_json: ["default"]`, so the captured
  artifacts match what the user's own `cargo build` produces.
- `prepare.sh` materializes the captured artifacts into the mock registry
  (`populate`) and emits `records.json`.
- `index-from-records` signs those records into the
  `index.<target>.<rustc>` slice inside the registry root — the bench
  counterpart of `stow-admin index export` + `index publish`, which need a
  live edge catalog the lane does not run.
- `stow-mock-registry serve` exposes the root over GHCR's anonymous token
  exchange; `run_bench.sh` points `STOW_REGISTRY_BASE_URL` at it and runs
  `stow index refresh` before measuring.
- `run_bench.sh` measures `cargo build`, `stow build`, `stow build
  --no-stow-resolver`, and the deps-prebuilt floor, each from a clean target
  directory.
- `projects.txt` is `name|version|git url|tag`.

Gotcha when comparing by hand: `stow build` has the wrapper append a
`--remap-path-prefix` to every rustc unit's argv — it travels through
`STOW_RUSTC_EXTRA_ARGS`, not `RUSTFLAGS`, where cargo's precedence rules
would discard a user's `.cargo/config.toml` rustflags — so a plain
`cargo build` in the same `target/` recompiles everything.
`run_bench.sh` keeps them in separate target directories.
