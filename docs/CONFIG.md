# `stow` configuration file

Every `stow` subcommand looks for a TOML config in the OS-standard
config directory. On macOS that's `~/Library/Application Support/stow/config.toml`;
on Linux it's `~/.config/stow/config.toml` (or `$XDG_CONFIG_HOME/stow/config.toml`
when set). Stow resolves the directory via the [`dirs` crate](https://docs.rs/dirs)
so the path follows your OS's conventions exactly.

Environment variables (see [`ENVIRONMENT.md`](ENVIRONMENT.md)) override
file values. Unknown keys are rejected at parse time.

## Schema

```toml
# REQUIRED: HTTPS URL of the edge worker that serves the public cache.
# May also be set via $STOW_EDGE_URL.
edge_url = "https://cache.stow-rs.example"

# Trust mode for cosign signature verification.
# - "github-ci": fulcio-rooted, intended for production. Default.
# - "mock-key":  accepts a single PEM public key for local mock setups.
verify_mode = "github-ci"

# REQUIRED when verify_mode = "mock-key": filesystem path to the trusted PEM.
# mock_public_key_path = "/etc/stow/mock-public.pem"

# Local artifact cache directory. Defaults to OS cache dir
# (~/Library/Caches/stow on macOS, $XDG_CACHE_HOME/stow on Linux).
# cache_dir = "/var/cache/stow"

# Soft cap on the on-disk artifact cache size in bytes. Default 20 GiB.
# When exceeded, stow LRU-prunes old bundles in the background.
# artifact_cache_max_bytes = 21474836480

# Per-request HTTP timeout (seconds) for the edge worker. Default 300.
# request_timeout_secs = 300

# How long the wrapper remembers a 404 from the edge before re-asking.
# negative_cache_ttl_secs = 300

# How long the parent driver caches the workspace's expanded graph
# response from /api/v1/catalog/graph. Default 300.
# graph_cache_ttl_secs = 300

# Circuit breaker: number of consecutive edge errors before stow
# bypasses the public cache for the rest of the run. Default 5.
# circuit_trip_threshold = 5

# Circuit breaker reset window (seconds). Default 60.
# circuit_reset_secs = 60
```

## Resolution order

The resolved `StowConfig` is the merge of, in order:

1. The parent process's `STOW_CONFIG_BLOB` env var (set automatically by
   `stow check` so children skip re-parsing the user config).
2. Per-key environment variables (`STOW_EDGE_URL`, etc.).
3. The TOML file at the OS config path.

When a value is missing from all three, the typed defaults above apply.
`edge_url` and `verify_mode=mock-key`'s `mock_public_key_path` have no
defaults — stow exits with an actionable error if they are unresolved.

## Project-level config

Stow does not read project-local TOML files; per-project tuning lives in
`.cargo/config.toml` (which `stow setup` writes for you). Specifically,
`stow setup` writes `[build] rustc-wrapper = <stow rustc shim>` and
`[env] CMAKE_C_COMPILER_LAUNCHER / CMAKE_CXX_COMPILER_LAUNCHER = <stow cc shim>`
so Cargo routes every compiler invocation through the stow wrappers when
invoked with `cargo` instead of `stow`.
