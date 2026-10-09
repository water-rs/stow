//! P1.1: process-local cache for the result of
//! `workspace_deps::resolve_exact_dependency_graph`.
//!
//! The `cargo <subcommand> --unit-graph` re-run is the single most
//! expensive thing on the cold path of `stow check` after the edge
//! round-trip — and its output is a pure function of cargo's own
//! inputs: the selected manifest, the invocation directory, subcommand
//! and forwarded args, `Cargo.lock`, every manifest cargo resolves, the
//! cargo config documents, rustflags/target/profile env vars, the
//! resolved target and rustc version. The key hashes the pre-query
//! inputs; the manifests cargo actually consulted — members and local
//! path-packages alike — ride the entry as recorded hashes and verify
//! on load (stow#551).
//!
//! The cache miss path simply runs the resolver (no behavior change). The
//! cache hit path skips the `--unit-graph` subprocess entirely.

use std::ffi::OsString;
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

/// Cargo flags that consume the following argument as a value, for the
/// normalization below — a bare positional on `test`/`bench` is the
/// libtest name filter and cannot change the unit graph (stow#551).
const VALUE_FLAGS: &[&[u8]] = &[
    b"--target",
    b"--manifest-path",
    b"--package",
    b"-p",
    b"--exclude",
    b"--features",
    b"--config",
    b"-Z",
    b"--jobs",
    b"-j",
    b"--target-dir",
    b"--profile",
    b"--message-format",
    b"--color",
    b"--registry",
    b"--index",
];

/// The forwarded args as cargo's unit-graph answer sees them:
/// everything after `--` selects libtest cases, and for `test`/`bench`
/// a bare positional is the test-name filter — neither changes the
/// graph, so neither may split the key.
fn normalized_args<'a>(action: &str, cargo_args: &'a [OsString]) -> Vec<&'a [u8]> {
    let args = cargo_args
        .iter()
        .take_while(|arg| arg.as_encoded_bytes() != b"--")
        .map(|arg| arg.as_encoded_bytes())
        .collect::<Vec<_>>();
    let mut normalized = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        let arg = args[index];
        index += 1;
        if (action == "test" || action == "bench") && !arg.starts_with(b"-") {
            continue;
        }
        normalized.push(arg);
        if VALUE_FLAGS.contains(&arg) && index < args.len() {
            normalized.push(args[index]);
            index += 1;
        }
    }
    normalized
}

/// Fingerprint key for one wrapped cargo invocation — every input the
/// `--unit-graph` re-run reads is hashed (stow#551).
///
/// v7: the canonical manifest path and invocation directory — sibling
/// members select different graphs (`stow build` in `a/` is not `b/`);
/// the resolved target and whether cargo was given one; normalized
/// args; the config documents as cargo reads them (files and `--config`
/// values alike); and `CARGO_UNSTABLE_*` alongside the other env inputs.
/// Member manifests leave the key — the entry's recorded local-manifest
/// hashes verify them on load.
pub fn cache_key(project: &crate::cargo_cmd::ProjectContext) -> stow_types::error::Result<String> {
    key_of(&KeyInputs {
        action: &project.action,
        cargo_args: &project.cargo_args,
        current_dir: &project.current_dir,
        manifest_path: &project.manifest_path,
        workspace_root: &project.workspace_root,
        target: &project.target,
        target_given: project.target_given,
        rustc_version: &project.rustc_version,
    })
}

/// The invocation fields [`cache_key`] hashes, borrowed for one
/// computation. A `ProjectContext` supplies them for the live build;
/// the miss-journal drain rebuilds them from the journal's context
/// sidecar so it can recompute the same key over the project's
/// *current* files — the same function of the same inputs is the same
/// graph, a different key is a changed project (stow#588).
pub struct KeyInputs<'a> {
    pub action: &'a str,
    pub cargo_args: &'a [OsString],
    pub current_dir: &'a Path,
    pub manifest_path: &'a Path,
    pub workspace_root: &'a Path,
    pub target: &'a str,
    pub target_given: bool,
    pub rustc_version: &'a str,
}

/// [`cache_key`] over a borrowed input set — the single function both
/// the build and the drain's memo check call.
pub fn key_of(project: &KeyInputs<'_>) -> stow_types::error::Result<String> {
    let mut hasher = Hasher::new();
    hasher.update(b"stow-lockfile-graph-cache-v8");
    hasher.update(project.action.as_bytes());
    hasher.update(&[0]);
    for arg in normalized_args(project.action, project.cargo_args) {
        hasher.update(arg);
        hasher.update(&[0]);
    }
    let cargo_dir = project
        .current_dir
        .canonicalize()
        .wrap_err("canonicalize cargo project dir")?;
    let manifest_path = project
        .manifest_path
        .canonicalize()
        .wrap_err("canonicalize cargo manifest path")?;
    hasher.update(manifest_path.as_os_str().as_encoded_bytes());
    hasher.update(&[0]);
    hasher.update(cargo_dir.as_os_str().as_encoded_bytes());
    hasher.update(&[0]);
    hasher.update(project.target.as_bytes());
    hasher.update(&[u8::from(project.target_given)]);
    hasher.update(project.rustc_version.as_bytes());
    hasher.update(&[0]);
    let workspace_root = project.workspace_root;
    hash_file_if_present(&mut hasher, &workspace_root.join("Cargo.lock"))?;
    hash_file_if_present(&mut hasher, &manifest_path)?;
    // Cargo reads its effective rustflags, linker, target and profile
    // out of these env vars — hash the inputs so a change misses
    // rather than serving a stale graph.
    for (key, value) in std::env::vars_os() {
        let Some(key) = key.to_str() else { continue };
        if matches!(key, "RUSTFLAGS" | "CARGO_ENCODED_RUSTFLAGS" | "RUSTC")
            || key.starts_with("CARGO_BUILD_")
            || key.starts_with("CARGO_TARGET_")
            || key.starts_with("CARGO_PROFILE_")
            || key.starts_with("CARGO_UNSTABLE_")
        {
            hasher.update(key.as_bytes());
            hasher.update(&[0]);
            hasher.update(value.as_encoded_bytes());
            hasher.update(&[0]);
        }
    }
    // Every config document cargo reads — files in merge order plus
    // each `--config` value — hashed as cargo sees them (source label
    // + parsed form).
    for (name, document) in
        crate::mold::cargo_config_documents(project.current_dir, project.cargo_args)
    {
        hasher.update(name.as_bytes());
        hasher.update(&[0]);
        hasher.update(document.to_string().as_bytes());
        hasher.update(&[0]);
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
    // The post-query half of the key: every local (path-source)
    // manifest cargo consulted must still hash the same — workspace
    // member edits and path dependencies outside the root are covered
    // without walking them into the key (stow#551).
    if !graph
        .local_manifests
        .iter()
        .all(super::workspace_deps::LocalManifestHash::verify)
    {
        return Ok(None);
    }
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

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{cache_key, normalized_args};
    use crate::cargo_cmd::{MetadataArgs, ProjectContext};
    use crate::workspace_deps::ExpandedDependencyGraph;

    fn project(dir: &std::path::Path, manifest: &std::path::Path) -> ProjectContext {
        ProjectContext {
            action: "check".to_owned(),
            cargo_args: Vec::new(),
            workspace_root: dir.to_path_buf(),
            current_dir: dir.to_path_buf(),
            current_dir_relative: PathBuf::new(),
            manifest_path: manifest.to_path_buf(),
            metadata_args: MetadataArgs::default(),
            target: "x86_64-unknown-linux-gnu".to_owned(),
            target_given: false,
            rustc_version: "1.99.0".to_owned(),
            mold_config_args: Vec::new(),
        }
    }

    /// `stow build` run in member `a/` and in member `b/` resolves a
    /// different manifest — the key must separate them or `b` would be
    /// served `a`'s graph (stow#551).
    #[test]
    fn sibling_members_key_separately() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::write(root.join("Cargo.lock"), "").expect("lockfile");
        for member in ["a", "b"] {
            let member_dir = root.join(member);
            std::fs::create_dir(&member_dir).expect("member dir");
            std::fs::write(
                member_dir.join("Cargo.toml"),
                "[package]\nname = \"member\"\nversion = \"0.1.0\"\n",
            )
            .expect("manifest");
        }
        let a = project(&root.join("a"), &root.join("a/Cargo.toml"));
        let b = project(&root.join("b"), &root.join("b/Cargo.toml"));
        assert_ne!(
            cache_key(&a).expect("key a"),
            cache_key(&b).expect("key b"),
            "the canonical manifest and invocation dir separate the keys"
        );
    }

    /// Args after `--` and the positional test-name filter select
    /// libtest cases, not the graph — they must not split the key
    /// (stow#551).
    #[test]
    fn test_filter_and_passthrough_args_do_not_split_the_key() {
        let key = |args: &[&str]| {
            normalized_args("test", &args.iter().map(OsString::from).collect::<Vec<_>>())
                .iter()
                .map(|arg| String::from_utf8_lossy(arg).into_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            key(&["--workspace", "filter_name", "--", "--nocapture"]),
            key(&["--workspace", "other_name", "--", "--ignored"]),
        );
        assert_eq!(
            key(&["--workspace", "--features", "f"]),
            key(&["--workspace", "--features", "f", "--", "x"]),
        );
        // Selection flags do change the key.
        assert_ne!(key(&["-p", "a"]), key(&["-p", "b"]));
    }

    /// Timing harness (not a test): `cargo test -p stow-cli --profile
    /// dist zed_cache -- --ignored --nocapture` measures the v7 key
    /// computation and the cache-hit validation (JSON decode +
    /// local-manifest hashing) over zed's ~250-member workspace
    /// (stow#551).
    #[test]
    #[ignore = "manual timing harness"]
    fn zed_cache_key_and_validation_cost() {
        let zed = PathBuf::from("/home/ubuntu/scratch/zed");
        let manifest = zed.join("Cargo.toml");
        let project = project(&zed, &manifest);
        let mut key_ms = Vec::new();
        for _ in 0..5 {
            let start = std::time::Instant::now();
            let key = cache_key(&project).expect("key");
            key_ms.push(start.elapsed().as_millis());
            assert_eq!(key.len(), 64, "blake3 hex key");
        }
        key_ms.sort_unstable();
        eprintln!("cache_key median {} ms (runs {key_ms:?})", key_ms[2]);

        let graph = smol::block_on(crate::workspace_deps::resolve_exact_dependency_graph(
            &manifest,
            "build",
            &[],
            Some("x86_64-unknown-linux-gnu"),
            &zed,
            "x86_64-unknown-linux-gnu",
            &stow_types::identity::WireRustcVersion::parse("1.91.1").unwrap(),
        ))
        .expect("resolve zed");
        let json = serde_json::to_string(&graph).expect("encode");
        eprintln!(
            "expanded_json {} KiB over {} local manifests",
            json.len() / 1024,
            graph.local_manifests.len()
        );
        let mut decode_ms = Vec::new();
        let mut verify_ms = Vec::new();
        for _ in 0..5 {
            let start = std::time::Instant::now();
            let decoded: ExpandedDependencyGraph = serde_json::from_str(&json).expect("decode");
            decode_ms.push(start.elapsed().as_millis());
            let start = std::time::Instant::now();
            assert!(
                decoded
                    .local_manifests
                    .iter()
                    .all(crate::workspace_deps::LocalManifestHash::verify)
            );
            verify_ms.push(start.elapsed().as_millis());
        }
        decode_ms.sort_unstable();
        verify_ms.sort_unstable();
        eprintln!("decode median {} ms (runs {decode_ms:?})", decode_ms[2]);
        eprintln!("verify median {} ms (runs {verify_ms:?})", verify_ms[2]);
    }
}
