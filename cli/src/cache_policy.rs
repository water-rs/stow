use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::rustc_args::ParsedRustcArgs;

const STOW_CACHE_POLICY_PATH_ENV: &str = "STOW_CACHE_POLICY_PATH";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CachePolicyEntry {
    pub target: String,
    pub crate_name: String,
}

/// The per-build policy directory a build's allow markers and local-build
/// provenance markers live under. Created empty and handed to cargo
/// immediately: the supervisor writes provenance markers into it during
/// the build, and the graph analysis's allow entries are committed into
/// the same directory as the build's background enrichment lands — the
/// checks that consult them read the directory per plan call, so a
/// late-arriving marker still gates the unit it names (stow#347).
pub async fn create_policy_dir(
    config: &crate::config::StowConfig,
) -> stow_types::error::Result<PathBuf> {
    async_fs::create_dir_all(config.graph_plan_dir())
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "create cache policy dir {}: {error}",
                config.graph_plan_dir().display()
            )
        })?;

    let dir = config.graph_plan_dir().join(format!(
        "cache-policy-{}-{}",
        std::process::id(),
        crate::state_db::now_millis()
    ));
    async_fs::create_dir_all(&dir).await.map_err(|error| {
        stow_types::stow_error!("create cache policy dir {}: {error}", dir.display())
    })?;

    Ok(dir)
}

/// Write `entries`' allow markers into the policy directory
/// [`create_policy_dir`] made.
pub async fn write_policy_entries(
    dir: &Path,
    entries: &[CachePolicyEntry],
) -> stow_types::error::Result<()> {
    for entry in entries {
        let file_path = allow_marker_path(dir, entry.target.as_str(), entry.crate_name.as_str());
        if let Some(parent) = file_path.parent() {
            async_fs::create_dir_all(parent).await.map_err(|error| {
                stow_types::stow_error!(
                    "create cache policy target dir {}: {error}",
                    parent.display()
                )
            })?;
        }
        async_fs::write(&file_path, []).await.map_err(|error| {
            stow_types::stow_error!("write cache policy marker {}: {error}", file_path.display())
        })?;
    }

    Ok(())
}

/// Cheap pre-identity gate: with a policy dir present, only crates the graph
/// analysis marked as cached are worth the identity computation + network
/// round trip. Keyed by canonical crate name — the only identity component
/// that is free to read from the rustc args and stable across cargo's
/// ephemeral metadata. A stale allow (name cached, variant missing) costs
/// one 404; a deny costs nothing.
///
/// `None` means "no policy configured" (standalone wrapper use) and the
/// caller treats it as allowed. `fallback_target` covers an invocation
/// that does not spell `--target`: the consumer target the driver
/// resolved for this build.
pub fn public_cache_allowed(
    policy_dir: Option<&Path>,
    parsed: &ParsedRustcArgs,
    fallback_target: Option<&str>,
) -> Option<bool> {
    let dir = policy_dir?;
    let target = parsed
        .target
        .clone()
        .or_else(|| fallback_target.map(str::to_owned))
        .filter(|target| !target.trim().is_empty())?;

    // The driver's entries name packages; `parsed.crate_name` is the lib
    // name `[lib] name` may have renamed (stow#578), so the package name
    // comes from the registry source path. An invocation without one is
    // a non-registry unit, which can hold no marker: the same answer a
    // missing marker file gives. This signature has no error channel —
    // its caller's decision type has none — so a probe error is logged
    // and treated as deny, not silently allowed.
    let crate_name = match stow_types::public_cache::detect_registry_crate_version(parsed) {
        Ok(Some((name, _version))) => name,
        Ok(None) => return Some(false),
        Err(error) => {
            tracing::warn!(
                crate_name = %parsed.crate_name,
                %error,
                "registry identity probe failed; treating invocation as not allowed"
            );
            return Some(false);
        }
    };
    let marker = allow_marker_path(dir, target.as_str(), &crate_name);
    Some(marker.exists())
}

/// The per-build policy directory this invocation was handed, when it is
/// running under a `stow check`/`stow build` that wrote one.
pub fn policy_dir() -> Option<PathBuf> {
    std::env::var_os(STOW_CACHE_POLICY_PATH_ENV).map(PathBuf::from)
}

pub fn cache_policy_env(path: &Path) -> (String, OsString) {
    (
        STOW_CACHE_POLICY_PATH_ENV.to_owned(),
        path.as_os_str().to_owned(),
    )
}

fn allow_marker_path(policy_dir: &Path, target: &str, crate_name: &str) -> PathBuf {
    policy_dir
        .join("allow")
        .join(target)
        .join(crate_name.replace('-', "_"))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    /// stow#578: the driver writes allow markers by package name, but the
    /// invocation spells the lib target name — a `[lib] name` rename must
    /// still find its marker through the registry source path.
    #[test]
    fn a_renamed_lib_matches_its_package_allow_marker() {
        let dir = tempfile::tempdir().expect("policy dir");
        let parsed = stow_types::rustc::ParsedRustcArgs::parse(&[
            OsString::from("--crate-name"),
            OsString::from("debug_unreachable"),
            OsString::from("--crate-type"),
            OsString::from("lib"),
            OsString::from("--target"),
            OsString::from("x86_64-unknown-linux-gnu"),
            OsString::from(
                "/root/.cargo/registry/src/index.crates.io-0123abcd/new_debug_unreachable-1.0.6/src/lib.rs",
            ),
        ])
        .expect("parse");
        assert_eq!(parsed.crate_name, "debug_unreachable");

        let marker = super::allow_marker_path(
            dir.path(),
            "x86_64-unknown-linux-gnu",
            "new_debug_unreachable",
        );
        std::fs::create_dir_all(marker.parent().unwrap()).expect("marker dir");
        std::fs::write(&marker, []).expect("write marker");

        assert_eq!(
            super::public_cache_allowed(Some(dir.path()), &parsed, None),
            Some(true),
            "the marker named for the package must cover the renamed lib unit"
        );
    }

    /// A unit with no registry source path is a non-registry invocation:
    /// it can hold no allow marker, so the answer is deny — the same as
    /// a missing marker file.
    #[test]
    fn a_non_registry_unit_is_denied() {
        let dir = tempfile::tempdir().expect("policy dir");
        let parsed = stow_types::rustc::ParsedRustcArgs::parse(&[
            OsString::from("--crate-name"),
            OsString::from("mycrate"),
            OsString::from("--crate-type"),
            OsString::from("lib"),
            OsString::from("--target"),
            OsString::from("x86_64-unknown-linux-gnu"),
            OsString::from("src/lib.rs"),
        ])
        .expect("parse");

        assert_eq!(
            super::public_cache_allowed(Some(dir.path()), &parsed, None),
            Some(false),
            "a non-registry unit gets the missing-marker answer"
        );
    }
}
