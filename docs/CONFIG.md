# `stow` configuration file

Every `stow` subcommand looks for a TOML config in the OS-standard
config directory. On macOS that's `~/Library/Application Support/stow/config.toml`;
on Linux it's `~/.config/stow/config.toml` (or `$XDG_CONFIG_HOME/stow/config.toml`
when set). Stow resolves the directory via the [`dirs` crate](https://docs.rs/dirs)
so the path follows your OS's conventions exactly.

Environment variables (see [`ENVIRONMENT.md`](ENVIRONMENT.md)) override
file values. Keys the file does not model are ignored, not rejected.

## Schema

```toml
# HTTPS URL of the edge worker that mints miss admissions.
# Defaults to the production edge, https://stow.waterui.dev; set it only for
# mock or staging runs. May also be set via $STOW_EDGE_URL.
edge_url = "https://stow.waterui.dev"

# OCI base URL (scheme://host/v2/repository) the signed index slices are
# pulled from (bundles stream through the edge). Defaults to the
# production GHCR repository; set it for mock runs.
# May also be set via $STOW_REGISTRY_BASE_URL.
# registry_base_url = "https://ghcr.io/v2/water-rs/stow-cache"

# Seconds a cached index slice may sit before `stow check`/`build`
# revalidates its manifest digest against the registry. Default 600.
# May also be set via $STOW_INDEX_REFRESH_SECS.
# index_refresh_secs = 600

# Trust mode for cosign signature verification.
# - "github-ci": fulcio-rooted, intended for production. Default.
# - "mock-key":  accepts a single PEM public key for local mock setups;
#                only a stow-cli built with `--features mock-verify` has it.
verify_mode = "github-ci"

# REQUIRED when verify_mode = "mock-key": filesystem path to the trusted PEM.
# mock_public_key_path = "/etc/stow/mock-public.pem"

# Local artifact cache directory. Defaults to `~/.stow` on every OS.
# May also be set via $STOW_CACHE_DIR.
# cache_dir = "/var/cache/stow"

# Soft cap on the on-disk artifact cache size in bytes. Default 20 GiB.
# When exceeded, stow LRU-prunes old bundles in the background.
# artifact_cache_max_bytes = 21474836480

# Per-request HTTP timeout (seconds) for the edge worker. Default 300.
# request_timeout_secs = 300

# How long the wrapper remembers an index miss (no row for a c_metadata)
# before re-checking the slice. Default 300.
# negative_cache_ttl_secs = 300

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
`verify_mode=mock-key`'s `mock_public_key_path` has no default — stow
exits with an actionable error if it is unresolved.

## Cargo-level config

Stow does not read project-local TOML files; the wiring lives in
`$CARGO_HOME/config.toml` — cargo's user-level configuration — which
`stow setup` writes for you. Specifically,
`stow setup` writes `[build] rustc-wrapper = <stow rustc shim>` and force-set
`[env]` entries pointing the C toolchain at the same shims — `CC`, `CXX`,
`CMAKE_C_COMPILER_LAUNCHER`, `CMAKE_CXX_COMPILER_LAUNCHER`, plus
`STOW_REAL_CC` / `STOW_REAL_CXX` recording the compilers those vars held
before the swap — so every Cargo invocation on the machine routes through
the stow wrappers.
