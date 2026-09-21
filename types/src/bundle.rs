//! OCI bundle layout and assembly.
//!
//! The media types and in-tar paths of a stow artifact bundle, the manifest
//! wire types the CLI reads after signature verification, and the assembler
//! that builds the bundle tar the trusted publish stage pushes and the edge
//! streams byte-for-byte.

use std::io::Cursor;

use serde::{Deserialize, Serialize};
use tar::{Builder, Header};

use crate::artifact::{ArtifactKind, NativeArtifacts, RustCrateType};
use crate::identity::{
    CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson, TargetTriple,
    WireRustcVersion,
};
use crate::platform::Profile;

/// Media type of the single-artifact bundle tar layer.
pub const STOW_BUNDLE_MEDIA_TYPE: &str = "application/vnd.stow.bundle.v1+tar";
/// Media type of an `.rlib` file inside a bundle.
pub const STOW_RLIB_MEDIA_TYPE: &str = "application/vnd.stow.rlib.v1";
/// Media type of an `.rmeta` file inside a bundle.
pub const STOW_RMETA_MEDIA_TYPE: &str = "application/vnd.stow.rmeta.v1";
/// Media type of a dylib file inside a bundle.
pub const STOW_DYLIB_MEDIA_TYPE: &str = "application/vnd.stow.dylib.v1";
/// Media type of a proc-macro dynamic library inside a bundle.
pub const STOW_PROC_MACRO_MEDIA_TYPE: &str = "application/vnd.stow.proc-macro.v1";
/// A tar of the build script's `OUT_DIR` tree, carried as its own layer.
pub const STOW_NATIVE_ARCHIVE_MEDIA_TYPE: &str = "application/vnd.stow.native-out-dir.v1+tar";
/// Media type suffix marking a zstd-compressed blob.
pub const STOW_ZSTD_MEDIA_TYPE_SUFFIX: &str = "+zstd";
/// Path of the per-artifact manifest inside a bundle tar.
pub const STOW_BUNDLE_MANIFEST_PATH: &str = "manifest.json";
/// Path of the OCI manifest JSON inside a bundle tar.
pub const STOW_OCI_MANIFEST_PATH: &str = "oci/manifest.json";
/// Path of the OCI config JSON inside a bundle tar — the document the cosign
/// signature covers.
pub const STOW_OCI_CONFIG_PATH: &str = "oci/config.json";
/// Directory inside a bundle tar holding Sigstore signature material.
pub const STOW_SIGSTORE_PAYLOAD_DIR: &str = "sigstore";
/// Directory inside a bundle tar holding the artifact's layer payloads.
pub const STOW_BUNDLE_FILES_DIR: &str = "files";
/// Media type of the signed artifact's OCI config blob.
pub const STOW_ARTIFACT_CONFIG_MEDIA_TYPE: &str = "application/vnd.stow.artifact.config.v1+json";
/// Media type of the `<tag>.bundle` artifact's OCI config blob.
pub const STOW_BUNDLE_CONFIG_MEDIA_TYPE: &str = "application/vnd.stow.bundle.config.v1+json";
/// Media type of an OCI image manifest, which every stow artifact is pushed as.
pub const OCI_IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
/// Media type cosign gives the simple-signing payload layer of a signature image.
pub const SIGSTORE_OCI_MEDIA_TYPE: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
/// Layer annotation carrying the base64 signature over the payload.
pub const SIGSTORE_SIGNATURE_ANNOTATION: &str = "dev.cosignproject.cosign/signature";
/// Layer annotation carrying the Rekor bundle JSON, when uploaded.
pub const SIGSTORE_BUNDLE_ANNOTATION: &str = "dev.sigstore.cosign/bundle";
/// Layer annotation carrying the PEM Fulcio certificate of the signer.
pub const SIGSTORE_CERT_ANNOTATION: &str = "dev.sigstore.cosign/certificate";

/// The tag cosign stores an artifact's signature image under: the manifest
/// digest with `:` replaced by `-`, plus `.sig`.
#[must_use]
pub fn sigstore_signature_tag(oci_digest: &str) -> String {
    format!("{}.sig", oci_digest.replace(':', "-"))
}

/// In-tar path of a layer payload.
#[must_use]
pub fn bundle_file_path(file_name: &str) -> String {
    format!("{STOW_BUNDLE_FILES_DIR}/{file_name}")
}

/// In-tar path of the `index`-th sigstore payload.
#[must_use]
pub fn sigstore_payload_path(index: usize) -> String {
    format!("{STOW_SIGSTORE_PAYLOAD_DIR}/payload-{index}.json")
}

/// Config blob of the `<tag>.bundle` artifact: which signed artifact the
/// bundle was assembled from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleArtifactConfig {
    /// Canonical stow reference of the signed artifact.
    pub oci_reference: String,
    /// Manifest digest of the signed artifact.
    pub oci_digest: String,
}

/// One cosign signature as read off the signature image: the payload blob
/// plus the annotations carried on its layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSignatureMaterial {
    /// In-tar path of the payload, `sigstore/payload-N.json`.
    pub payload_path: String,
    /// The simple-signing payload bytes exactly as the layer stores them.
    pub payload_bytes: Vec<u8>,
    /// Base64 signature over the payload.
    pub signature: String,
    /// PEM Fulcio certificate of the signer.
    pub certificate_pem: String,
    /// Rekor bundle JSON, when the signer uploaded one.
    pub rekor_bundle_json: Option<String>,
}

/// Everything a bundle tar is assembled from.
///
/// The signed artifact's raw manifest and config bytes (stored verbatim so
/// the CLI can re-hash them against the cosign payload), the signature
/// materials, and every layer's stored bytes in manifest order.
#[derive(Debug, Clone)]
pub struct BundleParts<'a> {
    /// Canonical stow reference of the signed artifact.
    pub oci_reference: &'a str,
    /// Manifest digest of the signed artifact.
    pub oci_digest: &'a str,
    /// The OCI manifest bytes exactly as the registry stores them.
    pub manifest_bytes: &'a [u8],
    /// The OCI config bytes exactly as the registry stores them.
    pub config_bytes: &'a [u8],
    /// The parsed config — `config_bytes` decoded.
    pub config: &'a ArtifactBlobConfig,
    /// Signature materials in signature-image layer order.
    pub signatures: &'a [BundleSignatureMaterial],
    /// Layer payloads in manifest order: the config's `outputs`, then the
    /// native archive when the config declares one. Each entry is the layer's
    /// stored (zstd) bytes; the media type is the file's storage media type.
    pub layers: &'a [BundleLayer<'a>],
}

/// One layer payload handed to [`assemble_bundle`].
#[derive(Debug, Clone)]
pub struct BundleLayer<'a> {
    /// Media type of the layer as the registry stores it.
    pub media_type: &'a str,
    /// Stored bytes of the layer.
    pub bytes: &'a [u8],
}

/// Assembly failed: the parts do not describe one consistent artifact.
#[derive(Debug, thiserror::Error)]
pub enum BundleAssemblyError {
    /// The bundle manifest could not be serialized.
    #[error("serialize bundle manifest: {0}")]
    SerializeManifest(serde_json::Error),
    /// A tar entry could not be written.
    #[error("build bundle tar: {0}")]
    BuildTar(std::io::Error),
    /// The layer list does not match the config's declared files.
    #[error("bundle layers do not match config outputs: {0}")]
    LayerMismatch(String),
}

/// Assemble the bundle tar for one signed artifact.
///
/// Entry order is part of the format: `manifest.json`, `oci/manifest.json`,
/// `oci/config.json`, each `sigstore/payload-N.json`, then `files/<name>`
/// for every layer in manifest order. Every entry is a regular file with
/// mode `0644`, so the same parts always produce the same bytes.
///
/// # Errors
/// Returns [`BundleAssemblyError`] when the layer count or a layer media
/// type disagrees with the config's declared files, or a tar write fails.
pub fn assemble_bundle(parts: &BundleParts<'_>) -> Result<Vec<u8>, BundleAssemblyError> {
    let expected = parts
        .config
        .outputs
        .iter()
        .chain(parts.config.native_archive.as_ref())
        .collect::<Vec<_>>();
    if expected.len() != parts.layers.len() {
        return Err(BundleAssemblyError::LayerMismatch(format!(
            "{} layers for {} declared files",
            parts.layers.len(),
            expected.len()
        )));
    }
    for (file, layer) in expected.iter().zip(parts.layers) {
        let storage_media_type = file.storage_media_type();
        if layer.media_type != storage_media_type {
            return Err(BundleAssemblyError::LayerMismatch(format!(
                "{} is stored as {} but the layer is {}",
                file.file_name, storage_media_type, layer.media_type
            )));
        }
    }

    let mut tar = Builder::new(Vec::new());
    let manifest = ArtifactBundleManifest {
        oci_reference: parts.oci_reference.to_owned(),
        oci_digest: parts.oci_digest.to_owned(),
        config: parts.config.clone(),
        sigstore_signatures: parts
            .signatures
            .iter()
            .map(|material| SigstoreSignature {
                payload_path: material.payload_path.clone(),
                signature: material.signature.clone(),
                certificate_pem: material.certificate_pem.clone(),
                rekor_bundle_json: material.rekor_bundle_json.clone(),
            })
            .collect(),
    };
    let manifest_json =
        serde_json::to_vec(&manifest).map_err(BundleAssemblyError::SerializeManifest)?;
    append_entry(&mut tar, STOW_BUNDLE_MANIFEST_PATH, &manifest_json)?;
    append_entry(&mut tar, STOW_OCI_MANIFEST_PATH, parts.manifest_bytes)?;
    append_entry(&mut tar, STOW_OCI_CONFIG_PATH, parts.config_bytes)?;
    for material in parts.signatures {
        append_entry(&mut tar, &material.payload_path, &material.payload_bytes)?;
    }
    for (file, layer) in expected.iter().zip(parts.layers) {
        append_entry(&mut tar, &bundle_file_path(&file.file_name), layer.bytes)?;
    }
    tar.into_inner().map_err(BundleAssemblyError::BuildTar)
}

fn append_entry(
    tar: &mut Builder<Vec<u8>>,
    path: &str,
    bytes: &[u8],
) -> Result<(), BundleAssemblyError> {
    let mut header = Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, path, Cursor::new(bytes))
        .map_err(BundleAssemblyError::BuildTar)
}

/// Manifest at `manifest.json` inside a bundle tar, describing the artifact
/// the bundle carries and the signatures covering it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBundleManifest {
    /// OCI reference the bundle was fetched from.
    pub oci_reference: String,
    /// OCI manifest digest the bundle was fetched as.
    pub oci_digest: String,
    /// Identity and file listing of the artifact; must equal the
    /// signature-covered `oci/config.json`.
    pub config: ArtifactBlobConfig,
    /// Sigstore signatures over the bundle's OCI config.
    pub sigstore_signatures: Vec<SigstoreSignature>,
}

/// Embedded JSON config describing one artifact bundle's identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBlobConfig {
    /// Stable hash of the trusted build's exact rustc invocation identity.
    pub compile_key: String,
    /// Crate name.
    pub crate_name: CrateName,
    /// Crate version.
    pub crate_version: CrateVersion,
    /// Cargo `-C metadata` value.
    pub c_metadata: CMetadata,
    /// Cargo `-C extra-filename` suffix.
    pub extra_filename: String,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Canonical features list.
    pub features_json: FeaturesJson,
    /// Sorted dependency identities driving the cache key.
    pub dependency_c_metadata_json: DependencyCMetadataJson,
    /// JSON-encoded compile keys of dependencies.
    pub dependency_compile_keys_json: String,
    /// Cargo profile.
    pub profile: Profile,
    /// Sorted, deduplicated emit modes.
    pub emit: Vec<String>,
    /// Bundle size in bytes.
    pub artifact_size: u64,
    /// Wall-clock milliseconds the captured rustc invocation took. Bundles
    /// published before the field existed carry no timing and count as zero
    /// CPU time saved.
    #[serde(default)]
    pub compile_millis: u64,
    /// Artifact kind.
    pub kind: ArtifactKind,
    /// Declared crate types.
    pub crate_types: Vec<RustCrateType>,
    /// Files in this bundle.
    pub outputs: Vec<ArtifactBundleFile>,
    /// Optional native artifacts.
    pub native: Option<NativeArtifacts>,
    /// The bundle file carrying `native`'s `OUT_DIR` tree, when there is one.
    ///
    /// Kept out of `outputs` because those are rustc products with a
    /// materialization path in the target directory; this is replay input for
    /// a build script. It rides as a normal zstd-compressed OCI layer, so the
    /// cosign signature covers it exactly as it covers every other layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_archive: Option<ArtifactBundleFile>,
}

/// One file inside an artifact bundle tar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBundleFile {
    /// File name as it appears inside the bundle.
    pub file_name: String,
    /// Media type of the uncompressed file.
    pub media_type: String,
    /// SHA-256 of the file's bytes, hex-encoded.
    pub sha256: String,
}

impl ArtifactBundleFile {
    /// Media type this file is stored under in the OCI layer — the plain
    /// media type plus the `+zstd` compression suffix.
    #[must_use]
    pub fn storage_media_type(&self) -> String {
        format!("{}{}", self.media_type, STOW_ZSTD_MEDIA_TYPE_SUFFIX)
    }
}

/// One Sigstore (cosign) signature over a bundle's OCI config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigstoreSignature {
    /// Path of the signed payload inside the bundle's `sigstore/` directory.
    pub payload_path: String,
    /// Signature over the payload.
    pub signature: String,
    /// PEM-encoded Fulcio certificate of the signing identity.
    pub certificate_pem: String,
    /// Rekor transparency-log bundle JSON, when the signer uploaded one.
    pub rekor_bundle_json: Option<String>,
}
