//! Repack an already-published node into the single-pack layout.
//!
//! A node published before bundles became one pack stores each output as
//! its own zstd layer, and its bundle carries each layer at
//! `files/<file name>`. Repacking reads such a node back from its bundle —
//! verifying its signature, every layer against the signed manifest and
//! every file's SHA-256 against the signed config — packs the same files as
//! one layer, and publishes it through the path a build publishes through.
//! The config blob is carried over byte for byte, so the node's identity
//! does not move; only the layer, the manifest digest, the signature and
//! the bundle are new.
//!
//! This module reads the layout it retires, which is why it exists apart
//! from the readers: it is deleted with the last sweep.

use oci_client::manifest::OciImageManifest;
use sha2::{Digest as _, Sha256};
use stow_types::api::ArtifactRecord;
use stow_types::bundle::STOW_PACK_MEDIA_TYPE;
use stow_types::error::Context as _;

use crate::artifacts::publish_packed;
use crate::bundle::pull_bundle;
use crate::client::RegistrySession;
use crate::verify::Trust;

// Removed, with the rest of the old-format reader in this module, after the final repack sweep.
/// Media type suffix the retired layout gave each per-file layer.
const RETIRED_LAYER_SUFFIX: &str = "+zstd";

/// The directory of a retired bundle holding each layer under its file's
/// name.
const RETIRED_FILES_DIR: &str = "files";

/// Whether `manifest` is already in the single-pack layout.
fn is_packed(manifest: &OciImageManifest) -> bool {
    matches!(manifest.layers.as_slice(), [layer] if layer.media_type == STOW_PACK_MEDIA_TYPE)
}

/// Repack the node `record` names, when it is still in the per-file
/// layout.
///
/// Returns `None` for a node already packed — nothing is written — and
/// otherwise the record to publish in its place: `record` with the new
/// artifact and bundle coordinates. `sign` signs the new manifest under the
/// publisher's identity, exactly as a build's publish does.
///
/// The node is trusted only after: its bundle hashes to the record's
/// `bundle_digest`, the manifest it carries to the record's `oci_digest`, a
/// signature whose certificate satisfies `policy` binds it to the record's
/// `oci_reference`, the config to the manifest's config digest, every layer
/// to its descriptor, and every decompressed file to the SHA-256 the signed
/// config records.
///
/// # Errors
///
/// Returns an error when any of those checks fails, the layers do not
/// match the config's files, or a push fails.
pub async fn repack_record<S, Fut>(
    session: &RegistrySession,
    trust: &Trust,
    policy: &(impl sigstore::bundle::verify::policy::VerificationPolicy + Sync),
    record: &ArtifactRecord,
    sign: &S,
) -> stow_types::error::Result<Option<ArtifactRecord>>
where
    S: Fn(String, String) -> Fut + Send + Sync,
    Fut: Future<Output = stow_types::error::Result<stow_types::bundle::BundleSignatureMaterial>>
        + Send,
{
    let oci_reference = record.oci_reference.as_str();
    let bundle = pull_bundle(session, record).await?;
    if is_packed(&bundle.manifest) {
        return Ok(None);
    }
    bundle
        .verify(trust, policy)
        .wrap_err_with(|| format!("verify the signature of {oci_reference}"))?;

    let files = bundle.config.packed_files().collect::<Vec<_>>();
    if bundle.manifest.layers.len() != files.len() {
        return Err(stow_types::stow_error!(
            "{oci_reference} has {} layers for {} declared files",
            bundle.manifest.layers.len(),
            files.len()
        ));
    }
    let mut stored = Vec::with_capacity(files.len());
    for (file, layer) in files.iter().zip(&bundle.manifest.layers) {
        let expected = format!("{}{RETIRED_LAYER_SUFFIX}", file.media_type);
        if layer.media_type != expected {
            return Err(stow_types::stow_error!(
                "{} of {oci_reference} is stored as {}, expected {expected}",
                file.file_name,
                layer.media_type
            ));
        }
        stored.push(
            bundle
                .layer(&format!("{RETIRED_FILES_DIR}/{}", file.file_name), layer)?
                .to_vec(),
        );
    }

    let declared = bundle.config.packed_files().cloned().collect::<Vec<_>>();
    let pack = smol::unblock(move || -> stow_types::error::Result<Vec<u8>> {
        let mut decoded = Vec::with_capacity(stored.len());
        for (file, stored) in declared.iter().zip(&stored) {
            let bytes = stow_shim::decompress(stored)
                .wrap_err_with(|| format!("decompress {}", file.file_name))?;
            let actual = hex::encode(Sha256::digest(&bytes));
            if actual != file.sha256 {
                return Err(stow_types::stow_error!(
                    "{} hashes to {actual}, the signed config records {}",
                    file.file_name,
                    file.sha256
                ));
            }
            decoded.push(bytes);
        }
        let named = declared
            .iter()
            .zip(&decoded)
            .map(|(file, bytes)| (file.file_name.as_str(), bytes.as_slice()))
            .collect::<Vec<_>>();
        stow_shim::pack(&named)
    })
    .await
    .wrap_err_with(|| format!("repack {oci_reference}"))?;

    let published = publish_packed(
        session,
        oci_reference,
        &bundle.config,
        &bundle.config_bytes,
        &pack,
        sign,
    )
    .await?;
    Ok(Some(ArtifactRecord {
        oci_digest: published.oci_digest,
        bundle_digest: published.bundle_digest,
        bundle_size: published.bundle_size,
        ..record.clone()
    }))
}
