//! The verified cache-consumption machinery `stow-build` reuses: the same
//! signed-index → digest-check → cosign-verify → inject chain the user CLI
//! runs, as a narrow facade over the CLI's internal modules. One
//! implementation serves both callers, so the builder cannot drift from the
//! verification a stranger's machine gets.

use std::path::Path;

use stow_types::index::ArtifactIndexRow;
use stow_types::rustc::ParsedRustcArgs;

use crate::artifact_cache::{self, CachedArtifactBundle};
use crate::fetch::{self, BundleRef};
use crate::inject;
use crate::verify;

use crate::config::StowConfig;

pub use crate::index::IndexSlice;

/// The edge/registry/verify-mode configuration the consumption path loads
/// the same way the CLI does — opaque so the builder goes through the same
/// entry points a user invocation would.
#[derive(Debug)]
pub struct ConsumeConfig(StowConfig);

impl ConsumeConfig {
    /// Load the config from the environment exactly as the CLI does.
    ///
    /// # Errors
    ///
    /// Returns an error when the environment config is invalid.
    pub fn load() -> stow_types::error::Result<Self> {
        StowConfig::load().map(Self)
    }
}

/// Pull and signature-verify the index slice for `(target, rustc_version)`
/// — the same fetch the resolver runs before any lookup.
///
/// # Errors
///
/// Returns an error when no usable slice can be produced; the caller
/// treats that as consumption being unavailable, never as data.
pub async fn ensure_slice(
    config: &ConsumeConfig,
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<IndexSlice> {
    crate::index::ensure_slice(&config.0, target, rustc_version).await
}

/// A verified published bundle staged for a build task's sandbox, with the
/// two identity fields the capture wrapper cross-checks before injecting.
#[derive(Debug)]
pub struct ServedBundle {
    /// The stable compile key the bundle was published under.
    pub compile_key: String,
    /// The crate name the bundle's identity was verified against.
    pub crate_name: String,
    inner: CachedArtifactBundle,
}

/// Why a row the signed index names could not be staged.
///
/// The two are not the same failure and must not be handled the same way.
/// Bytes that never arrived are the ordinary state of a cache: the crate
/// has not been built for this slice yet, the edge is unreachable, GHCR
/// returned a 404. Bytes that arrived and then failed the digest,
/// identity or signature check are not ordinary at all — the signed index
/// vouched for that artifact, so either the publisher produced something
/// it cannot stand behind or someone has write access to the registry
/// they should not have. Compiling quietly past that would hide the one
/// class of bug the whole verification chain exists to surface, and it
/// would hide it on the machine that produces what every user installs.
#[derive(Debug)]
pub enum StageFailure {
    /// The bundle never arrived. The unit compiles; nothing is wrong.
    Unavailable(stow_types::error::Error),
    /// The bundle arrived and did not verify against what the signed
    /// index vouches for.
    Unverifiable(stow_types::error::Error),
}

impl std::fmt::Display for StageFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(error) | Self::Unverifiable(error) => error.fmt(f),
        }
    }
}

/// Download, digest-check, cosign-verify and stage the bundle `row` names
/// under `entry_dir`, for the build sandbox's read-only grant.
///
/// The chain is the wrapper's own: bytes stream from the edge byte path
/// digest-checked against the row's `bundle_digest`, the bundle's identity
/// fields must byte-match the signature-covered `oci/config.json`, and the
/// cosign signature must verify against the pinned `build-crate.yml`
/// identity — anything less and the call errors before a byte lands.
///
/// # Errors
///
/// [`StageFailure::Unavailable`] when the bundle could not be fetched,
/// [`StageFailure::Unverifiable`] when it arrived and failed any check.
pub async fn stage_verified_bundle(
    config: &ConsumeConfig,
    slice: &IndexSlice,
    row: &ArtifactIndexRow,
    entry_dir: &Path,
) -> Result<(), StageFailure> {
    let target = slice.index.header.target.as_str();
    let rustc_version = slice.index.header.rustc_version.as_str();
    let bundle_ref = BundleRef::from_index_row(target, rustc_version, row);
    let bytes = fetch::download_bundle_bytes(&config.0, &bundle_ref)
        .await
        .map_err(|error| {
            StageFailure::Unavailable(stow_types::error::Error::msg(format!(
                "fetch bundle for `{}` {}: {error}",
                row.crate_name, row.version
            )))
        })?;
    // Past this point the bytes are in hand and the index vouched for
    // them, so every remaining failure is a statement about the artifact
    // rather than about reachability.
    let bundle = fetch::parse_downloaded_bundle(bytes)
        .await
        .map_err(StageFailure::Unverifiable)?;
    fetch::validate_bundle_identity(
        &bundle,
        row.crate_name.as_str(),
        row.c_metadata.as_str(),
        target,
        rustc_version,
    )
    .map_err(StageFailure::Unverifiable)?;
    verify::verify_bundle_signature(&config.0, &bundle)
        .await
        .map_err(StageFailure::Unverifiable)?;
    artifact_cache::store_bundle_entry_dir(entry_dir, &bundle)
        .map_err(StageFailure::Unverifiable)?;
    Ok(())
}

/// Load a bundle [`stage_verified_bundle`] staged under `store_dir`, when
/// the entry exists and parses — a miss is exactly a cold cache and the
/// calling unit compiles.
///
/// # Errors
///
/// Returns an error when the entry exists but its manifest is unreadable.
pub fn load_served_bundle(
    store_dir: &Path,
    lease_dir: &Path,
    compile_key: &str,
) -> stow_types::error::Result<Option<ServedBundle>> {
    let Some(bundle) = artifact_cache::load_bundle_entry_dir(
        &store_dir.join(compile_key),
        lease_dir,
        compile_key,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(ServedBundle {
        compile_key: bundle.compile_key.clone(),
        crate_name: bundle.crate_name.clone(),
        inner: bundle,
    }))
}

/// Inject a served bundle's outputs as the artifacts `parsed` requested —
/// the same write the user's wrapper performs on a cache hit.
///
/// # Errors
///
/// Returns an error when an output cannot be materialized.
pub async fn serve_bundle_outputs(
    parsed: &ParsedRustcArgs,
    bundle: &ServedBundle,
) -> stow_types::error::Result<()> {
    inject::write_artifacts(
        parsed,
        &bundle.inner,
        inject::OutputDirWriters::UntrustedCodeToo,
    )
    .await
}
