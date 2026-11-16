//! Read a node back from its bundle — the one place a node is published.
//!
//! A node's `<tag>.bundle` carries the signed manifest and config byte for
//! byte, the signature material and the layer bytes, so an operator tool
//! that re-reads a node (repack, re-sign) checks everything the signature
//! covers from the bundle alone.

use std::collections::BTreeMap;
use std::io::Read as _;

use oci_client::manifest::{OciDescriptor, OciImageManifest};
use stow_types::api::ArtifactRecord;
use stow_types::bundle::{
    ArtifactBlobConfig, ArtifactBundleManifest, BundleSignatureMaterial, STOW_BUNDLE_MANIFEST_PATH,
    STOW_OCI_CONFIG_PATH, STOW_OCI_MANIFEST_PATH,
};
use stow_types::error::Context as _;
use stow_types::registry::verify_oci_digest;

use crate::client::RegistrySession;
use crate::verify::{Trust, verify_materials};

/// A node's bundle, checked against the record naming it: the bundle
/// hashes to the record's `bundle_digest`, its manifest to the record's
/// `oci_digest`, and its config to the manifest's config descriptor.
///
/// The signatures are not verified here — [`Self::verify`] checks them
/// under the policy the caller pins.
#[derive(Debug)]
pub struct PulledBundle {
    /// The signed reference the record names.
    pub oci_reference: String,
    /// The signed manifest's digest.
    pub oci_digest: String,
    /// The signed manifest.
    pub manifest: OciImageManifest,
    /// The signed config blob, byte for byte.
    pub config_bytes: Vec<u8>,
    /// `config_bytes` decoded.
    pub config: ArtifactBlobConfig,
    /// The signature material the bundle carries, in bundle order.
    pub signatures: Vec<BundleSignatureMaterial>,
    /// Every other entry of the tar, by path.
    entries: BTreeMap<String, Vec<u8>>,
}

impl PulledBundle {
    /// Require a signature whose certificate satisfies `policy` to bind
    /// the record's reference at its manifest digest.
    ///
    /// # Errors
    ///
    /// No signature the bundle carries verifies.
    pub fn verify(
        &self,
        trust: &Trust,
        policy: &(impl sigstore::bundle::verify::policy::VerificationPolicy + Sync),
    ) -> stow_types::error::Result<()> {
        verify_materials(
            trust,
            &self.oci_reference,
            &self.oci_digest,
            &self.signatures,
            policy,
        )
    }

    /// The bytes of the entry at `path`, required to be the layer
    /// `descriptor` names.
    ///
    /// # Errors
    ///
    /// The bundle has no such entry, or it does not hash to the
    /// descriptor's digest.
    pub fn layer(
        &self,
        path: &str,
        descriptor: &OciDescriptor,
    ) -> stow_types::error::Result<&[u8]> {
        let bytes = self.entries.get(path).ok_or_else(|| {
            stow_types::stow_error!("the bundle of {} lacks {path}", self.oci_reference)
        })?;
        verify_oci_digest(bytes, &descriptor.digest).map_err(|error| {
            stow_types::stow_error!("{path} of {}: {error}", self.oci_reference)
        })?;
        Ok(bytes)
    }
}

/// Pull the bundle `record` names and check it against the record.
///
/// # Errors
///
/// The bundle cannot be pulled, or it fails any check of
/// [`PulledBundle`].
pub async fn pull_bundle(
    session: &RegistrySession,
    record: &ArtifactRecord,
) -> stow_types::error::Result<PulledBundle> {
    let bytes = session
        .pull_blob(&record.bundle_digest)
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "pull bundle {} of {}: {error}",
                record.bundle_digest,
                record.oci_reference
            )
        })?;
    let record = record.clone();
    smol::unblock(move || {
        read_bundle(&bytes, &record).wrap_err_with(|| {
            format!(
                "read bundle {} of {}",
                record.bundle_digest, record.oci_reference
            )
        })
    })
    .await
}

fn read_bundle(bytes: &[u8], record: &ArtifactRecord) -> stow_types::error::Result<PulledBundle> {
    verify_oci_digest(bytes, &record.bundle_digest)?;
    let mut entries = BTreeMap::new();
    let mut archive = tar::Archive::new(bytes);
    for entry in archive.entries().wrap_err("read the bundle entries")? {
        let mut entry = entry.wrap_err("read a bundle entry")?;
        let path = entry
            .path()
            .wrap_err("read a bundle entry path")?
            .to_string_lossy()
            .into_owned();
        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .wrap_err_with(|| format!("read bundle entry {path}"))?;
        if entries.insert(path.clone(), contents).is_some() {
            return Err(stow_types::stow_error!("the bundle repeats {path}"));
        }
    }
    let mut take = |path: &str| {
        entries
            .remove(path)
            .ok_or_else(|| stow_types::stow_error!("the bundle has no {path}"))
    };
    let bundle_manifest: ArtifactBundleManifest =
        serde_json::from_slice(&take(STOW_BUNDLE_MANIFEST_PATH)?)
            .wrap_err("parse the bundle manifest")?;
    let manifest_bytes = take(STOW_OCI_MANIFEST_PATH)?;
    let config_bytes = take(STOW_OCI_CONFIG_PATH)?;
    if bundle_manifest.oci_reference != record.oci_reference
        || bundle_manifest.oci_digest != record.oci_digest
    {
        return Err(stow_types::stow_error!(
            "the bundle names {}@{}, the record {}@{}",
            bundle_manifest.oci_reference,
            bundle_manifest.oci_digest,
            record.oci_reference,
            record.oci_digest
        ));
    }
    verify_oci_digest(&manifest_bytes, &record.oci_digest).wrap_err("the signed manifest")?;
    let manifest: OciImageManifest =
        serde_json::from_slice(&manifest_bytes).wrap_err("parse the signed manifest")?;
    verify_oci_digest(&config_bytes, &manifest.config.digest).wrap_err("the signed config")?;
    let config: ArtifactBlobConfig =
        serde_json::from_slice(&config_bytes).wrap_err("parse the signed config")?;
    let signatures = bundle_manifest
        .sigstore_signatures
        .into_iter()
        .map(|signature| {
            let payload_bytes = entries.remove(&signature.payload_path).ok_or_else(|| {
                stow_types::stow_error!("the bundle lacks {}", signature.payload_path)
            })?;
            Ok(BundleSignatureMaterial {
                payload_path: signature.payload_path,
                payload_bytes,
                signature: signature.signature,
                certificate_pem: signature.certificate_pem,
                rekor_bundle_json: signature.rekor_bundle_json,
            })
        })
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    Ok(PulledBundle {
        oci_reference: record.oci_reference.clone(),
        oci_digest: record.oci_digest.clone(),
        manifest,
        config_bytes,
        config,
        signatures,
        entries,
    })
}
