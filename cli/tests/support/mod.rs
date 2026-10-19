//! The environment every integration test's `stow-cli` invocation shares.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The environment a hermetic `stow-cli` invocation needs: `edge_url` as
/// both the edge and the OCI registry base — without the second the CLI
/// reaches the real registry, and once the public index covers a
/// fixture's crates an "all-miss" build is no longer one (stow#608) — an
/// isolated cache dir, a `home` the child's home directories all point
/// at, and loopback's proxy exclusions.
pub fn hermetic_stow_env(command: &mut Command, edge_url: &str, cache_dir: &Path, home: &Path) {
    sealed_home_env(command, home);
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
        // Every other `STOW_*` knob `StowConfig::load` and the wrapper
        // environment read is removed for the same reason — the test's
        // own values go on the command after this call (stow#800).
        .env("STOW_VERIFY_MODE", "github-ci")
        .env_remove("STOW_CONFIG_BLOB")
        .env_remove("STOW_INDEX_REFRESH_SECS")
        .env_remove("STOW_ARTIFACT_CACHE_MAX_BYTES")
        .env_remove("STOW_MOCK_PUBLIC_KEY_PATH")
        .env_remove("STOW_DISABLE_PUBLIC_CACHE")
        .env_remove("STOW_ENABLE_SEMANTIC_FALLBACK")
        .env_remove("STOW_ENABLE_PREBUILT_DEPS")
        .env_remove("STOW_PUBLIC_CACHE_RUSTC_VERSION")
        .env_remove("STOW_PUBLIC_CACHE_TARGET")
        .env_remove("STOW_CACHE_POLICY_PATH")
        .env_remove("STOW_EXPANDED_GRAPH_PATH")
        .env_remove("STOW_PREFETCH_ARTIFACTS_PATH")
        .env_remove("STOW_SERVE_MAP_FILE")
        .env_remove("STOW_SUPERVISOR_ENDPOINT")
        .env_remove("STOW_SUPERVISOR_TOKEN")
        .env_remove("STOW_SUPERVISOR_BINARY")
        .env_remove("STOW_TRACE_FILE")
        .env_remove("STOW_TRACE_WRAPPED_COMPILERS")
        .env_remove("STOW_IDENTITY_TRACE")
        .env_remove("STOW_NO_ANALYTICS")
        .env_remove("STOW_REAL_CC")
        .env_remove("STOW_REAL_CXX")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost");
}

/// The home a hermetic child process gets: `HOME` and the platform's
/// per-user config/data/cache variables all point under `home`, so
/// `~/.stow`, the user-level stow config, `~/.gitconfig` and
/// `~/.cargo/config.toml` (when `CARGO_HOME` is unset) can never leak in
/// from the developer's machine. `RUSTUP_HOME` still names the real
/// toolchains — a rustup shim under a redirected `HOME` would resolve
/// none. Compiler-hijack variables a developer might export are
/// cleared; a test that needs one sets it after this call.
///
/// Every directory a variable names exists before the child runs: on
/// Windows `dirs` resolves the config and local-data dirs through
/// `SHGetKnownFolderPath` without `KF_FLAG_DONT_VERIFY`, which fails on a
/// folder that does not exist, and stow then skips its config entirely.
pub fn sealed_home_env(command: &mut Command, home: &Path) {
    let dirs = [
        ("HOME", home.to_path_buf()),
        ("USERPROFILE", home.to_path_buf()),
        ("XDG_CONFIG_HOME", home.join(".config")),
        ("XDG_DATA_HOME", home.join(".local").join("share")),
        ("XDG_CACHE_HOME", home.join(".cache")),
        ("APPDATA", home.join("AppData").join("Roaming")),
        ("LOCALAPPDATA", home.join("AppData").join("Local")),
    ];
    for (key, dir) in dirs {
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|error| panic!("create {key} dir {}: {error}", dir.display()));
        command.env(key, dir);
    }
    command
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("CC")
        .env_remove("CXX");
    if let Some(rustup_home) = real_rustup_home() {
        command.env("RUSTUP_HOME", rustup_home);
    }
}

/// The toolchain home the machine's rustup shims resolve: `RUSTUP_HOME`
/// when the developer exports it, else `~/.rustup` under the real home —
/// resolved before `sealed_home_env` redirects `HOME` on the child.
fn real_rustup_home() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("RUSTUP_HOME") {
        return Some(PathBuf::from(home));
    }
    let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(key).map(|home| PathBuf::from(home).join(".rustup"))
}
