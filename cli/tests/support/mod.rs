//! The environment every integration test's `stow-cli` invocation shares.

use std::path::Path;
use std::process::Command;

/// The environment a hermetic `stow-cli` invocation needs: `edge_url` as
/// both the edge and the OCI registry base — without the second the CLI
/// reaches the real registry, and once the public index covers a
/// fixture's crates an "all-miss" build is no longer one (stow#608) — an
/// isolated cache dir, and loopback's proxy exclusions.
pub fn hermetic_stow_env(command: &mut Command, edge_url: &str, cache_dir: &Path) {
    command
        .env("STOW_EDGE_URL", edge_url)
        .env(
            "STOW_REGISTRY_BASE_URL",
            format!("{edge_url}/water-rs/stow"),
        )
        .env("STOW_CACHE_DIR", cache_dir)
        // Isolate from the developer's ambient stow config: a user-level
        // `verify_mode = "mock-key"` (or an inherited `STOW_CONFIG_BLOB`)
        // would make this binary reject the config and skip the cache.
        .env("STOW_VERIFY_MODE", "github-ci")
        .env_remove("STOW_CONFIG_BLOB")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost");
}
