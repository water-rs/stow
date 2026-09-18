//! OCI bundle layout: the media types and in-tar paths of a stow artifact
//! bundle, plus the manifest wire types the CLI reads after signature
//! verification.

use serde::{Deserialize, Serialize};

use crate::artifact::{ArtifactKind, NativeArtifacts, RustCrateType};
use crate::identity::{
    CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson, TargetTriple,
    WireRustcVersion,
};
use crate::platform::Profile;

/// Media type of the single-artifact bundle tar layer.
pub const STOW_BUNDLE_MEDIA_TYPE: &str = "application/vnd.stow.bundle.v1+tar";
/// Media type of a batch bundle tar carrying several artifacts.
pub const STOW_BATCH_BUNDLE_MEDIA_TYPE: &str = "application/vnd.stow.batch.v1+tar";
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
/// Path of the top-level manifest inside a batch bundle tar.
pub const STOW_BATCH_MANIFEST_PATH: &str = "batch-manifest.json";
/// Directory inside a batch tar holding each artifact's bundle.
pub const STOW_BATCH_BUNDLES_DIR: &str = "bundles";
/// Path of the OCI manifest JSON inside a bundle tar.
pub const STOW_OCI_MANIFEST_PATH: &str = "oci/manifest.json";
/// Path of the OCI config JSON inside a bundle tar — the document the cosign
/// signature covers.
pub const STOW_OCI_CONFIG_PATH: &str = "oci/config.json";
/// Directory inside a bundle tar holding Sigstore signature material.
pub const STOW_SIGSTORE_PAYLOAD_DIR: &str = "sigstore";

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

/// Manifest describing one batch artifact request response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBatchManifest {
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Per-artifact entries (one per request entry, including misses).
    pub entries: Vec<ArtifactBatchManifestEntry>,
}

/// One entry in a batch artifact response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBatchManifestEntry {
    /// Crate name.
    pub crate_name: CrateName,
    /// Cargo `-C metadata` value.
    pub c_metadata: CMetadata,
    /// Path to the bundle within the tar, or `None` if the artifact is missing.
    pub bundle_path: Option<String>,
}
