//! P1.1: process-local cache for the result of
//! `workspace_deps::resolve_exact_dependency_graph`.
//!
//! `cargo metadata` is the single most expensive thing on the cold path of
//! `stow check` after the edge graph round-trip — and its output is a pure
//! function of `Cargo.lock`, the workspace `Cargo.toml`, the target triple,
//! and the rustc version. We hash those four into a cache key and store the
//! JSON-encoded resolved graph in the workspace state DB.
//!
//! The cache miss path simply runs the resolver (no behavior change). The
//! cache hit path skips the `cargo metadata` subprocess entirely.

use std::path::Path;
use std::time::Duration;

use blake3::Hasher;
use stow_types::error::Context;

use crate::config::StowConfig;
use crate::state_db::{db_int, duration_millis, now_millis};
use crate::workspace_deps::ExpandedDependencyGraph;

/// 24h: long enough to survive a working day, short enough to not pin truly
/// stale data forever. Cache invalidation is otherwise driven by the
/// fingerprint key (lock changes always miss).
const CACHE_TTL: Duration = Duration::from_hours(24);

/// Compute the fingerprint key for a workspace+target+rustc combination.
pub fn cache_key(
    workspace_root: &Path,
    manifest_path: &Path,
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<String> {
    let mut hasher = Hasher::new();
    // v2: the cached payload now carries the per-package feature graphs
    // alongside the expanded entries.
    hasher.update(b"stow-lockfile-graph-cache-v2");
    hasher.update(target.as_bytes());
    hasher.update(&[0]);
    hasher.update(rustc_version.as_bytes());
    hasher.update(&[0]);
    hash_file_if_present(&mut hasher, &workspace_root.join("Cargo.lock"))?;
    hash_file_if_present(&mut hasher, &workspace_root.join("Cargo.toml"))?;
    if manifest_path != workspace_root.join("Cargo.toml") {
        hash_file_if_present(&mut hasher, manifest_path)?;
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn hash_file_if_present(hasher: &mut Hasher, path: &Path) -> stow_types::error::Result<()> {
    match std::fs::read(path) {
        Ok(bytes) => {
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(&bytes);
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            hasher.update(&u64::MAX.to_le_bytes());
            Ok(())
        }
        Err(error) => Err(error)
            .wrap_err_with(|| format!("read {} for lockfile graph cache key", path.display())),
    }
}

/// Look up a cached expanded graph by fingerprint key. Returns `None` on
/// miss or expired TTL.
#[tracing::instrument(name = "stow.lockfile_graph_cache.load", skip_all)]
pub async fn load(
    config: &StowConfig,
    key: &str,
) -> stow_types::error::Result<Option<ExpandedDependencyGraph>> {
    let pool = config.state_db_pool().await?;
    let now_ms: i64 = db_int(now_millis(), "lockfile graph cache current time")?;
    let ttl_ms: i64 = db_int(duration_millis(CACHE_TTL), "lockfile graph cache TTL")?;
    sqlx::query("DELETE FROM lockfile_graph_cache WHERE ? - inserted_at_ms >= ?")
        .bind(now_ms)
        .bind(ttl_ms)
        .execute(&pool)
        .await?;
    let row: Option<(String,)> =
        sqlx::query_as("SELECT expanded_json FROM lockfile_graph_cache WHERE cache_key = ?")
            .bind(key)
            .fetch_optional(&pool)
            .await?;
    let Some((json,)) = row else {
        return Ok(None);
    };
    let graph: ExpandedDependencyGraph =
        serde_json::from_str(&json).wrap_err("decode cached lockfile graph")?;
    Ok(Some(graph))
}

/// Store an expanded graph under a fingerprint key.
#[tracing::instrument(name = "stow.lockfile_graph_cache.store", skip_all)]
pub async fn store(
    config: &StowConfig,
    key: &str,
    graph: &ExpandedDependencyGraph,
) -> stow_types::error::Result<()> {
    let pool = config.state_db_pool().await?;
    let json = serde_json::to_string(graph).wrap_err("encode lockfile graph")?;
    let now_ms: i64 = db_int(now_millis(), "lockfile graph cache current time")?;
    sqlx::query(
        "INSERT OR REPLACE INTO lockfile_graph_cache (cache_key, inserted_at_ms, expanded_json) \
         VALUES (?, ?, ?)",
    )
    .bind(key)
    .bind(now_ms)
    .bind(json)
    .execute(&pool)
    .await?;
    Ok(())
}
